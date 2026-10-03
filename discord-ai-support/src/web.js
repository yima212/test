const express = require("express");
const crypto = require("crypto");
const Stripe = require("stripe");

const config = require("./config");
const {
  getGuildConfig,
  saveGuildConfig,
  getGuildDashboardStats,
  getRecentGuildTickets,
  createDashboardSession,
  getDashboardSession,
  deleteDashboardSession,
  createOAuthState,
  consumeOAuthState,
  cleanupExpiredSessions,
  getGuildPlan,
  saveGuildSubscription,
  getGuildUsage,
  createActivationCodes,
  redeemActivationCode,
  disableActivationCode,
  listActivationCodes,
  getActivationCodeStats,
  recordAuditLog,
  getRecentAuditLogs
} = require("./db");

const {
  PLAN_DEFINITIONS,
  getPlanDefinition,
  normalizePlan,
  formatLimit
} = require("./plans");

const app = express();
app.set("trust proxy", 1);
const stripe = config.stripeSecretKey ? new Stripe(config.stripeSecretKey) : null;

const rateBuckets = new Map();
const RATE_WINDOW = 60 * 1000;

function clientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || "unknown").slice(0, 120);
}

function rateLimit(prefix, max, windowMs = RATE_WINDOW) {
  return (req, res, next) => {
    const now = Date.now();
    const key = prefix + ":" + clientIp(req);
    const current = rateBuckets.get(key);
    if (!current || now - current.startedAt >= windowMs) {
      rateBuckets.set(key, { startedAt: now, count: 1 });
      return next();
    }

    current.count += 1;
    if (current.count <= max) return next();

    const retryAfter = Math.max(1, Math.ceil((windowMs - (now - current.startedAt)) / 1000));
    res.setHeader("Retry-After", retryAfter);
    return res.status(429).send("Demasiadas solicitudes. Espera unos segundos e inténtalo de nuevo.");
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (now - bucket.startedAt > 15 * 60 * 1000) rateBuckets.delete(key);
  }
}, 5 * 60 * 1000).unref();

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "POST" && req.path !== "/api/stripe/webhook") {
    const origin = String(req.headers.origin || "").trim();
    const referer = String(req.headers.referer || "").trim();
    const expectedOrigin = config.dashboardUrl;

    const validOrigin = origin
      ? origin === expectedOrigin
      : (referer && referer.startsWith(expectedOrigin + "/"));

    if (!validOrigin) {
      return res.status(403).send("Origen de solicitud no permitido.");
    }
  }

  next();
});

app.use(express.json({
  limit: "32kb",
  verify: (req, _res, buf) => {
    if (req.path === "/api/stripe/webhook") req.rawBody = Buffer.from(buf);
  }
}));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

const DISCORD_API = "https://discord.com/api/v10";
const BOT_PERMISSIONS = "93200";

function cleanText(value, max = 5000) {
  return String(value ?? "").slice(0, max);
}

function escapeHtml(value, max = 5000) {
  return cleanText(value, max)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("es-ES", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Europe/Madrid"
  }).format(new Date(value));
}

async function issueSession(user, guilds) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  await createDashboardSession({
    token,
    user,
    guilds,
    expiresAt
  });

  return token;
}

function parseCookies(header = "") {
  return Object.fromEntries(
    header
      .split(";")
      .map(x => x.trim())
      .filter(Boolean)
      .map(x => {
        const i = x.indexOf("=");
        return i < 0 ? [x, ""] : [x.slice(0, i), decodeURIComponent(x.slice(i + 1))];
      })
  );
}

async function currentSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies["__Host-dashboard_session"] || cookies.dashboard_session;
  return token ? getDashboardSession(token) : null;
}

async function userCanManageGuild(discordGuild, userId) {
  if (!discordGuild || !userId) return false;
  if (discordGuild.ownerId === userId) return true;

  try {
    const member = await discordGuild.members.fetch(userId);
    return Boolean(
      member.permissions.has("Administrator") ||
      member.permissions.has("ManageGuild")
    );
  } catch (error) {
    console.warn("[SECURITY] No se pudo verificar permisos en vivo:", error.message);
    return false;
  }
}

async function requireManagedGuild(req, session) {
  const guild = session?.guilds?.find(g => g.id === req.params.guildId);
  if (!guild) return null;

  const discordGuild = client.guilds.cache.get(guild.id);
  if (!discordGuild) return null;

  const allowed = await userCanManageGuild(discordGuild, session.user.id);
  return allowed ? { guild, discordGuild } : null;
}

function isManager(guild) {
  if (!guild) return false;
  if (guild.owner === true) return true;

  try {
    const permissions = BigInt(guild.permissions || "0");
    const MANAGE_GUILD = 32n;
    const ADMINISTRATOR = 8n;
    return (
      (permissions & MANAGE_GUILD) === MANAGE_GUILD ||
      (permissions & ADMINISTRATOR) === ADMINISTRATOR
    );
  } catch {
    return false;
  }
}

function discordIconUrl(guild) {
  if (!guild?.icon) return "";
  return `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png?size=128`;
}

function discordUserAvatarUrl(user) {
  if (!user?.id || !user?.avatar) return "";
  return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=96`;
}

function isFounder(session) {
  return Boolean(
    session?.user?.id &&
    config.founderId &&
    session.user.id === config.founderId
  );
}

function activationReasonMessage(reason) {
  const messages = {
    invalid: "El código no existe o no es válido.",
    used: "Ese código ya fue utilizado.",
    disabled: "Ese código está desactivado.",
    expired: "Ese código ha caducado.",
    plan_active: "Este servidor ya tiene un plan activo."
  };
  return messages[reason] || "No se pudo activar el código.";
}

function htmlShell(title, body, user = null) {
  const avatar = discordUserAvatarUrl(user);
  const nav = user
    ? `<div class="nav-actions">
        <a class="nav-link" href="/dashboard">Dashboard</a>
        <a class="nav-link" href="/pricing">Planes</a>
        <a class="nav-link nav-primary" href="/onboarding">Primeros pasos</a>
        ${isFounder({ user }) ? '<a class="nav-link" href="/admin">Admin</a>' : ''}
        <div class="profile-chip">
          ${avatar ? '<img src="' + escapeHtml(avatar, 300) + '" alt="">' : '<span class="profile-fallback">' + escapeHtml((user.username || "?").slice(0,1).toUpperCase(),1) + '</span>'}
          <span>${escapeHtml(user.username, 80)}</span>
        </div>
        <a class="nav-link danger-link" href="/logout">Salir</a>
      </div>`
    : `<div class="nav-actions">
        <a class="nav-link" href="#features">Funciones</a>
        <a class="nav-link" href="#pricing">Precios</a>
        <a class="nav-link" href="/onboarding">Cómo funciona</a>
        <a class="btn btn-sm" href="/auth/discord">Entrar con Discord</a>
      </div>`;

  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#090912">
<title>${escapeHtml(title, 120)} · AI Support</title>
<style>
:root{color-scheme:dark;--bg:#07070b;--panel:#10101a;--panel2:#151522;--line:rgba(255,255,255,.09);--line2:rgba(255,255,255,.15);--text:#f7f7fb;--muted:#9da0b4;--muted2:#74778b;--brand:#6d5dfc;--brand2:#8e82ff;--cyan:#44d8ff;--success:#39d98a;--warning:#ffbf5f;--danger:#ff718a;--shadow:0 24px 90px rgba(0,0,0,.42);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;color:var(--text);min-height:100vh;background:radial-gradient(circle at 10% -10%,rgba(109,93,252,.20),transparent 28%),radial-gradient(circle at 92% 4%,rgba(68,216,255,.12),transparent 24%),radial-gradient(circle at 50% 60%,rgba(109,93,252,.06),transparent 32%),var(--bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:40px 40px;mask-image:linear-gradient(to bottom,black,transparent 75%)}a{color:inherit;text-decoration:none}button,input,textarea,select{font:inherit}.wrap{max-width:1240px;margin:0 auto;padding:0 24px 28px}
.site-nav{position:sticky;top:0;z-index:30;margin:0 -24px;padding:16px 24px;background:rgba(7,7,11,.78);backdrop-filter:blur(18px);border-bottom:1px solid rgba(255,255,255,.06)}.nav-inner{max-width:1240px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:11px;font-weight:900}.brand-mark{width:36px;height:36px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(145deg,var(--brand),#3c2fd8);box-shadow:0 10px 28px rgba(109,93,252,.35);font-size:18px}.brand-copy strong{display:block;font-size:14px;letter-spacing:.08em}.brand-copy span{display:block;color:var(--muted2);font-size:10px;letter-spacing:.12em;text-transform:uppercase;margin-top:1px}.nav-actions{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.nav-link{padding:9px 11px;border-radius:11px;color:#c3c5d4;font-weight:700;font-size:13px;transition:.2s}.nav-link:hover{background:rgba(255,255,255,.05);color:#fff}.nav-primary{color:#fff;background:rgba(109,93,252,.15);border:1px solid rgba(109,93,252,.30)}.danger-link:hover{color:#ffb2bf;background:rgba(255,113,138,.08)}.profile-chip{display:flex;align-items:center;gap:8px;padding:5px 9px 5px 5px;border:1px solid var(--line);background:rgba(255,255,255,.03);border-radius:999px;font-size:12px;font-weight:800}.profile-chip img,.profile-fallback{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;object-fit:cover;background:linear-gradient(145deg,#2b2b3b,#151520)}
.hero{padding:76px 0 44px}.hero-grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(360px,.95fr);gap:36px;align-items:center}.hero h1{margin:14px 0 16px;max-width:840px;font-size:clamp(44px,6.4vw,84px);line-height:.96;letter-spacing:-.055em}.hero p{max-width:760px;color:#c9cada;font-size:18px;line-height:1.7;margin:0}.eyebrow{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid rgba(109,93,252,.30);background:rgba(109,93,252,.10);border-radius:999px;color:#ddd9ff;font-size:11px;font-weight:900;letter-spacing:.09em;text-transform:uppercase}.eyebrow-dot{width:7px;height:7px;border-radius:50%;background:var(--brand2);box-shadow:0 0 16px rgba(142,130,255,.9)}.hero-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:26px}.btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;min-height:44px;padding:12px 16px;border-radius:13px;border:1px solid transparent;background:linear-gradient(145deg,var(--brand2),var(--brand));color:#fff;font-weight:900;font-size:13px;cursor:pointer;box-shadow:0 10px 28px rgba(109,93,252,.22);transition:.2s transform,.2s filter,.2s box-shadow}.btn:hover{transform:translateY(-1px);filter:brightness(1.05);box-shadow:0 14px 34px rgba(109,93,252,.28)}.btn.alt{background:rgba(255,255,255,.045);border-color:var(--line2);box-shadow:none}.btn.ghost{background:transparent;border-color:var(--line2);box-shadow:none}.btn.danger{background:rgba(255,113,138,.09);border-color:rgba(255,113,138,.20);color:#ffc0ca;box-shadow:none}.btn-sm{min-height:38px;padding:9px 13px;font-size:12px}.hero-trust{display:flex;gap:16px;flex-wrap:wrap;margin-top:22px;color:var(--muted);font-size:12px;font-weight:700}.hero-trust span{display:inline-flex;align-items:center;gap:7px}.hero-trust b{color:#fff}
.visual-wrap{position:relative}.glow{position:absolute;inset:8% 8% 2%;background:radial-gradient(circle,var(--brand),transparent 60%);filter:blur(60px);opacity:.20}.ticket-ui{position:relative;border:1px solid rgba(255,255,255,.11);background:linear-gradient(160deg,rgba(25,25,39,.96),rgba(10,10,18,.98));border-radius:26px;padding:16px;box-shadow:var(--shadow);overflow:hidden}.ticket-top{display:flex;align-items:center;justify-content:space-between;padding:5px 5px 14px;border-bottom:1px solid var(--line)}.ticket-title{display:flex;align-items:center;gap:10px}.ticket-icon{width:40px;height:40px;border-radius:13px;display:grid;place-items:center;background:rgba(109,93,252,.15);border:1px solid rgba(109,93,252,.25)}.ticket-title strong{font-size:13px}.ticket-title span{display:block;color:var(--muted);font-size:11px;margin-top:2px}.ticket-status{font-size:10px;font-weight:900;padding:6px 8px;border-radius:999px;color:#93f2c0;background:rgba(57,217,138,.08);border:1px solid rgba(57,217,138,.18)}.chat{padding:18px 6px 8px;display:grid;gap:12px}.chat-row{display:flex;gap:9px;align-items:flex-end}.chat-row.me{justify-content:flex-end}.bubble{max-width:76%;padding:11px 12px;border-radius:15px;background:#181827;border:1px solid var(--line);color:#d9dbea;font-size:12px;line-height:1.5}.bubble.ai{background:linear-gradient(150deg,rgba(109,93,252,.16),rgba(68,216,255,.07));border-color:rgba(109,93,252,.22)}.bubble.me{background:#24243a;color:#fff}.chat-avatar{width:26px;height:26px;border-radius:9px;display:grid;place-items:center;font-size:12px;font-weight:900;background:#242438}.ticket-footer{display:flex;align-items:center;gap:8px;padding:10px 5px 2px}.ticket-input{flex:1;height:40px;border-radius:12px;border:1px solid var(--line);background:#0d0d15;color:var(--muted);display:flex;align-items:center;padding:0 12px;font-size:11px}.ticket-send{width:40px;height:40px;border-radius:12px;border:1px solid rgba(109,93,252,.25);background:rgba(109,93,252,.14);display:grid;place-items:center;color:#e6e1ff}
.section-block{padding:38px 0}.section-head{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:18px}.section-head h2{margin:8px 0 0;font-size:28px;letter-spacing:-.04em}.section-head p{margin:5px 0 0;color:var(--muted);font-size:14px}.pill{display:inline-flex;align-items:center;padding:7px 10px;border-radius:999px;background:rgba(255,255,255,.045);border:1px solid var(--line);color:#d7d9e7;font-size:11px;font-weight:800}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.grid-4{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:linear-gradient(180deg,rgba(19,19,30,.90),rgba(12,12,20,.94));border:1px solid var(--line);border-radius:20px;padding:20px;box-shadow:0 15px 50px rgba(0,0,0,.18)}.card h2,.card h3{margin:0 0 7px}.card p{margin:0;color:var(--muted);line-height:1.55}.feature-icon{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:rgba(109,93,252,.11);border:1px solid rgba(109,93,252,.20);margin-bottom:14px;font-size:17px}.feature-card h3{font-size:15px}.feature-card p{font-size:13px}.step-number{font-size:11px;font-weight:900;color:#bcb6ff;letter-spacing:.12em;text-transform:uppercase}.step-card h3{margin-top:7px}.price-card{position:relative;display:flex;flex-direction:column}.price-card.featured{border-color:rgba(109,93,252,.42);box-shadow:0 22px 70px rgba(74,57,210,.18)}.price-badge{position:absolute;top:14px;right:14px;padding:6px 8px;border-radius:999px;background:rgba(109,93,252,.16);border:1px solid rgba(109,93,252,.28);color:#dedaff;font-size:10px;font-weight:900}.price-name{font-size:12px;color:#bbbcd0;font-weight:900;letter-spacing:.1em;text-transform:uppercase}.price-value{font-size:48px;font-weight:950;letter-spacing:-.06em;margin:10px 0 2px}.price-value span{font-size:13px;color:var(--muted);font-weight:800;letter-spacing:0}.price-list{display:grid;gap:8px;margin:14px 0 20px}.price-list div{color:#c4c6d4;font-size:12px}.price-list b{color:#fff}
.stats-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;border:1px solid var(--line);background:var(--line);border-radius:18px;overflow:hidden}.stat-block{background:rgba(13,13,21,.95);padding:18px}.stat-block strong{display:block;font-size:22px;letter-spacing:-.04em}.stat-block span{display:block;color:var(--muted);font-size:11px;margin-top:4px}.dashboard-hero{padding:42px 0 22px;display:flex;justify-content:space-between;gap:20px;align-items:end}.dashboard-hero h1{font-size:44px;margin:8px 0 7px;letter-spacing:-.05em}.dashboard-hero p{margin:0;color:var(--muted);max-width:700px}.dashboard-actions{display:flex;gap:9px;flex-wrap:wrap}.server-card{display:flex;align-items:center;gap:14px;min-height:88px}.server-meta{min-width:0;flex:1}.server-name{font-weight:900;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.server-icon{width:54px;height:54px;flex:0 0 auto;border-radius:16px;display:grid;place-items:center;background:#191925;border:1px solid var(--line2);overflow:hidden;font-size:17px}.server-icon img{width:100%;height:100%;object-fit:cover}.status{display:inline-flex;align-items:center;gap:7px;color:var(--muted);font-size:11px;margin-top:5px}.status-dot{width:7px;height:7px;border-radius:50%}.online{background:var(--success);box-shadow:0 0 13px rgba(57,217,138,.55)}.offline{background:#6c6d7c}.kpi{font-size:34px;font-weight:950;letter-spacing:-.05em}.stat-label{color:var(--muted);font-size:11px;font-weight:700;margin-top:4px}
.side-layout{display:grid;grid-template-columns:225px minmax(0,1fr);gap:18px;align-items:start}.sidebar{position:sticky;top:84px;padding:9px}.sidebar a{display:flex;align-items:center;gap:9px;padding:10px 11px;border-radius:11px;color:#bfc2d1;font-size:12px;font-weight:800;margin-bottom:3px}.sidebar a:hover,.sidebar a.active{background:rgba(109,93,252,.10);color:#fff}.section{scroll-margin-top:96px}.section-title{display:flex;align-items:end;justify-content:space-between;gap:12px;margin-bottom:11px}.section-title h2{font-size:21px;letter-spacing:-.03em}.section-title .muted{color:var(--muted);font-size:11px}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.field.full{grid-column:1/-1}label{display:block;font-weight:800;font-size:12px;margin:0 0 7px}input,textarea,select{width:100%;border:1px solid #2c2d39;background:#0c0c14;color:#fafaff;border-radius:12px;padding:11px 12px;outline:none;transition:.2s}input:focus,textarea:focus,select:focus{border-color:rgba(109,93,252,.72);box-shadow:0 0 0 3px rgba(109,93,252,.12)}textarea{min-height:165px;resize:vertical}.help{margin-top:6px;color:var(--muted2);font-size:11px;line-height:1.45}.toolbar{display:flex;gap:10px;justify-content:space-between;align-items:center;flex-wrap:wrap}.actions{display:flex;gap:8px;flex-wrap:wrap}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px;background:rgba(0,0,0,.10)}table{width:100%;border-collapse:collapse;min-width:640px}th,td{padding:11px 13px;border-bottom:1px solid rgba(255,255,255,.055);text-align:left;font-size:12px}th{color:#8e91a5;font-weight:800;background:rgba(255,255,255,.025)}tr:last-child td{border-bottom:0}.badge{display:inline-flex;padding:5px 8px;border-radius:999px;font-size:10px;font-weight:900;border:1px solid var(--line2)}.badge.success{color:#9bf4c4;background:rgba(57,217,138,.07);border-color:rgba(57,217,138,.17)}.badge.warning{color:#ffd38a;background:rgba(255,191,95,.07);border-color:rgba(255,191,95,.18)}.badge.muted{background:rgba(255,255,255,.04);color:#aaaec0}.notice{padding:13px 14px;border-radius:13px;background:rgba(109,93,252,.08);border:1px solid rgba(109,93,252,.18);color:#dbd8ff;font-size:12px;line-height:1.55}.notice.success{background:rgba(57,217,138,.07);border-color:rgba(57,217,138,.15);color:#bbf8d6}.empty{padding:42px 22px;text-align:center}.empty .feature-icon{margin:0 auto 12px}.empty h3{margin-bottom:6px}.legal{max-width:860px;margin:0 auto;padding:52px 0}.legal h1{font-size:48px;letter-spacing:-.05em;margin:8px 0 12px}.legal h2{font-size:20px;margin:30px 0 8px}.legal p,.legal li{color:#b8bbca;line-height:1.7;font-size:14px}.legal ul{padding-left:20px}.footer{padding:48px 0 8px;color:#707386;font-size:11px}.footer-inner{display:flex;align-items:center;justify-content:space-between;gap:12px;border-top:1px solid var(--line);padding-top:18px}.footer-links{display:flex;gap:12px;flex-wrap:wrap}.footer-links a:hover{color:#fff}
@media(max-width:980px){.hero-grid{grid-template-columns:1fr}.grid-4{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:repeat(2,1fr)}.stats-strip{grid-template-columns:repeat(2,1fr)}.side-layout{grid-template-columns:1fr}.sidebar{position:static;display:flex;overflow:auto;gap:6px;padding:0}.sidebar a{white-space:nowrap}.form-grid{grid-template-columns:1fr}.field.full{grid-column:auto}.dashboard-hero{align-items:start;flex-direction:column}}
@media(max-width:680px){.wrap{padding:0 15px 20px}.site-nav{margin:0 -15px;padding:13px 15px}.nav-inner{align-items:flex-start}.nav-actions{justify-content:flex-end}.nav-actions .nav-link{display:none}.nav-actions .profile-chip{display:flex}.hero{padding:50px 0 30px}.hero h1{font-size:46px}.hero p{font-size:16px}.grid,.grid-4{grid-template-columns:1fr}.stats-strip{grid-template-columns:1fr 1fr}.dashboard-hero h1{font-size:36px}.card{padding:17px}.legal h1{font-size:38px}.footer-inner{align-items:flex-start;flex-direction:column}}

.app-shell{display:grid;grid-template-columns:232px minmax(0,1fr);gap:18px;align-items:start}
.app-sidebar{position:sticky;top:88px;background:rgba(14,14,24,.84);border:1px solid var(--line);border-radius:22px;padding:12px;box-shadow:0 18px 55px rgba(0,0,0,.22)}
.app-sidebar .server-switch{display:flex;align-items:center;gap:10px;padding:10px;border-radius:14px;background:rgba(255,255,255,.035);border:1px solid var(--line);margin-bottom:12px}
.app-sidebar .server-switch .mini-icon{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:#202033;overflow:hidden;font-weight:900}
.app-sidebar .server-switch .mini-icon img{width:100%;height:100%;object-fit:cover}
.app-sidebar .server-switch .name{min-width:0;flex:1}.app-sidebar .server-switch strong{display:block;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.app-sidebar .server-switch span{display:block;color:var(--muted2);font-size:10px;margin-top:2px}
.side-group{margin:12px 6px 7px;color:#6f7287;font-size:10px;font-weight:900;letter-spacing:.11em;text-transform:uppercase}
.side-link{display:flex;align-items:center;gap:10px;padding:10px 11px;border-radius:12px;color:#bfc2d2;font-size:12px;font-weight:800;margin:3px 0}
.side-link:hover,.side-link.active{background:linear-gradient(90deg,rgba(109,93,252,.18),rgba(109,93,252,.05));color:#fff;border:1px solid rgba(109,93,252,.14)}
.side-link .icon{width:18px;text-align:center;color:#bdb7ff}
.app-main{min-width:0}
.page-top{display:flex;justify-content:space-between;align-items:end;gap:18px;margin:34px 0 18px}.page-top h1{margin:7px 0 5px;font-size:42px;letter-spacing:-.05em}.page-top p{margin:0;color:var(--muted);font-size:13px}
.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.metric-card{padding:18px;background:linear-gradient(180deg,rgba(21,21,34,.95),rgba(12,12,20,.94));border:1px solid var(--line);border-radius:18px}.metric-card .metric-top{display:flex;justify-content:space-between;gap:10px;align-items:center;color:var(--muted);font-size:11px;font-weight:800}.metric-card .metric-icon{width:31px;height:31px;border-radius:10px;display:grid;place-items:center;background:rgba(109,93,252,.12);border:1px solid rgba(109,93,252,.18)}.metric-card .metric-value{font-size:31px;font-weight:950;letter-spacing:-.05em;margin-top:12px}.metric-card .metric-sub{font-size:11px;color:var(--muted2);margin-top:3px}
.progress{height:8px;background:#0d0d15;border-radius:999px;overflow:hidden;border:1px solid rgba(255,255,255,.06)}.progress>span{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,var(--brand),var(--cyan))}
.two-col{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(280px,.65fr);gap:14px}.panel-card{background:linear-gradient(180deg,rgba(18,18,29,.93),rgba(11,11,18,.95));border:1px solid var(--line);border-radius:20px;padding:19px}.panel-card h3{margin:0 0 5px}.panel-card .sub{color:var(--muted);font-size:11px}
.activity-bars{height:185px;display:flex;align-items:flex-end;gap:12px;padding:22px 8px 4px}.activity-bar{flex:1;min-width:18px;border-radius:8px 8px 3px 3px;background:linear-gradient(180deg,#8e82ff,rgba(109,93,252,.24));border:1px solid rgba(142,130,255,.18);box-shadow:0 10px 28px rgba(109,93,252,.10)}.activity-axis{display:flex;justify-content:space-between;color:#676a7f;font-size:9px;padding:0 8px}
.donut-wrap{display:flex;align-items:center;gap:18px}.donut{width:138px;height:138px;border-radius:50%;background:conic-gradient(var(--brand) 0 44%,#44d8ff 44% 72%,#ffbf5f 72% 86%,#4b4c5a 86% 100%);position:relative;flex:0 0 auto}.donut:after{content:"";position:absolute;inset:24px;border-radius:50%;background:#10101a;border:1px solid var(--line)}.legend{display:grid;gap:10px;flex:1}.legend-row{display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:11px;color:#bfc1cf}.legend-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:7px;background:#6d5dfc}.legend-row:nth-child(2) .legend-dot{background:#44d8ff}.legend-row:nth-child(3) .legend-dot{background:#ffbf5f}.legend-row:nth-child(4) .legend-dot{background:#4b4c5a}
.tabbar{display:flex;gap:6px;overflow:auto;padding-bottom:3px;border-bottom:1px solid var(--line);margin-bottom:16px}.tab-btn{border:0;background:transparent;color:#8e91a5;padding:10px 13px;border-radius:10px;font-weight:900;font-size:11px;cursor:pointer;white-space:nowrap}.tab-btn:hover,.tab-btn.active{color:#fff;background:rgba(109,93,252,.12)}.tab-panel{display:none}.tab-panel.active{display:block}
.form-section{background:linear-gradient(180deg,rgba(20,20,31,.94),rgba(12,12,20,.96));border:1px solid var(--line);border-radius:18px;padding:18px}.form-section h3{margin:0 0 5px}.form-section .sub{color:var(--muted);font-size:11px;margin-bottom:16px}.sticky-save{position:sticky;bottom:12px;display:flex;justify-content:flex-end;padding-top:12px}
.code-box{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px}.code-box input{text-align:center;letter-spacing:.08em;font-weight:900}
.profile-banner{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border-radius:15px;background:linear-gradient(90deg,rgba(109,93,252,.10),rgba(68,216,255,.05));border:1px solid rgba(109,93,252,.17);margin-bottom:14px}
.admin-layout{display:grid;grid-template-columns:208px minmax(0,1fr);gap:18px;align-items:start}.admin-sidebar{position:sticky;top:88px;padding:10px;background:rgba(14,14,24,.84);border:1px solid var(--line);border-radius:20px}.admin-title{font-size:12px;font-weight:900;letter-spacing:.09em;text-transform:uppercase;padding:10px 11px;color:#fff}
.fade-in{animation:fadeIn .35s ease-out}@keyframes fadeIn{from{opacity:.5;transform:translateY(5px)}to{opacity:1;transform:none}}
@media(max-width:980px){.app-shell,.admin-layout{grid-template-columns:1fr}.app-sidebar,.admin-sidebar{position:static;display:flex;overflow:auto;gap:6px}.side-group{display:none}.side-link{white-space:nowrap}.metric-grid{grid-template-columns:repeat(2,1fr)}.two-col{grid-template-columns:1fr}}
@media(max-width:680px){.metric-grid{grid-template-columns:1fr}.page-top{margin-top:24px}.page-top h1{font-size:35px}.stats-strip{grid-template-columns:1fr 1fr}.code-box{grid-template-columns:1fr}.app-sidebar,.admin-sidebar{padding:7px}.profile-banner{align-items:flex-start;flex-direction:column}}

</style>
</head>
<body><div class="wrap">
<header class="site-nav"><div class="nav-inner">
<a class="brand" href="${user ? "/dashboard" : "/"}"><span class="brand-mark">✦</span><span class="brand-copy"><strong>AI SUPPORT</strong><span>Discord automation</span></span></a>
${nav}
</div></header>
${body}
<footer class="footer"><div class="footer-inner"><span>AI Support · Discord SaaS</span><div class="footer-links"><a href="/terms">Términos</a><a href="/privacy">Privacidad</a><a href="/onboarding">Cómo funciona</a><a href="/auth/discord">Acceso Discord</a></div></div></footer>
</div></body></html>`;
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "discord-ai-support" });
});

app.get("/auth/discord", rateLimit("oauth-start", 12, 10 * 60 * 1000), async (_req, res) => {
  if (!config.discordClientSecret) {
    return res.status(503).send(htmlShell("Configuración pendiente",
      '<div class="card"><h2>Falta Discord OAuth</h2><p class="muted">Añade DISCORD_CLIENT_SECRET en Railway y vuelve a intentarlo.</p></div>'
    ));
  }

  const state = crypto.randomBytes(20).toString("hex");
  await createOAuthState(
    state,
    new Date(Date.now() + 10 * 60 * 1000).toISOString()
  );

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.dashboardUrl + "/auth/discord/callback",
    response_type: "code",
    scope: "identify guilds",
    state
  });

  res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
});

app.get("/auth/discord/callback", rateLimit("oauth-callback", 30, 10 * 60 * 1000), async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || !(await consumeOAuthState(state))) {
      return res.status(400).send("Invalid OAuth state.");
    }

    const tokenBody = new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.discordClientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: config.dashboardUrl + "/auth/discord/callback"
    });

    const tokenResponse = await fetch(DISCORD_API + "/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: tokenBody
    });

    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok) throw new Error(tokenData.error_description || "OAuth token exchange failed");

    const headers = { Authorization: "Bearer " + tokenData.access_token };
    const [userResponse, guildResponse] = await Promise.all([
      fetch(DISCORD_API + "/users/@me", { headers }),
      fetch(DISCORD_API + "/users/@me/guilds", { headers })
    ]);

    const user = await userResponse.json();
    const guildPayload = await guildResponse.json();

    if (!guildResponse.ok || !Array.isArray(guildPayload)) {
      throw new Error("Discord no devolvió la lista de servidores.");
    }

    const guilds = guildPayload.filter(isManager);

    console.log(
      `[OAUTH] user=${user.username || user.id} guilds=${guildPayload.length} manageable=${guilds.length}`
    );

    const sessionToken = await issueSession(user, guilds);
    res.setHeader(
      "Set-Cookie",
      "__Host-dashboard_session=" + encodeURIComponent(sessionToken) + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400"
    );
    res.redirect("/dashboard");
  } catch (error) {
    console.error("OAuth error:", error);
    res.status(500).send(htmlShell("OAuth error",
      '<div class="card"><h2>⚠️ No se pudo iniciar sesión</h2><p class="error">'+escapeHtml(error.message,1000)+'</p></div>'
    ));
  }
});

app.get("/logout", async (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies["__Host-dashboard_session"] || cookies.dashboard_session;
  if (token) await deleteDashboardSession(token);
  res.setHeader("Set-Cookie", [
    "__Host-dashboard_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    "dashboard_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  ]);
  res.redirect("/");
});

app.get("/", async (req, res) => {
  const session = await currentSession(req);
  if (session) return res.redirect("/dashboard");

  const plans = Object.values(PLAN_DEFINITIONS).map(def => {
    const suffix = def.key === "pro" ? '<span>/mes</span>' : (def.key === "lifetime" ? '<span> único</span>' : '<span>/mes</span>');
    const action = def.key === "free" ? "Empezar gratis" : (def.key === "pro" ? "Suscribirse" : "Comprar Lifetime");
    return '<article class="card price-card ' + (def.key === "pro" ? "featured" : "") + '">' +
      (def.key === "pro" ? '<div class="price-badge">MÁS USADO</div>' : '') +
      '<div class="price-name">' + escapeHtml(def.name,40) + '</div>' +
      '<div class="price-value">' + escapeHtml(def.price,20) + suffix + '</div>' +
      '<p>' + escapeHtml(def.key === "free" ? "Ideal para empezar" : def.key === "pro" ? "Para servidores en crecimiento" : "Pago único, para siempre", 100) + '</p>' +
      '<div class="price-list"><div>✓ ' + formatLimit(def.ticketsPerMonth,"tickets/mes") + '</div><div>✓ ' + formatLimit(def.aiRepliesPerMonth,"respuestas IA/mes") + '</div><div>✓ ' + formatLimit(def.knowledgeChars,"caracteres KB") + '</div></div>' +
      '<a class="btn ' + (def.key === "pro" ? "" : "alt") + '" href="/auth/discord">' + action + '</a></article>';
  }).join("");

  res.send(htmlShell("AI Support", `
    <section class="hero">
      <div class="hero-grid">
        <div>
          <div class="eyebrow"><span class="eyebrow-dot"></span>Discord support · powered by AI</div>
          <h1>Automatiza el soporte de tu servidor con <span style="background:linear-gradient(90deg,#8e82ff,#44d8ff);-webkit-background-clip:text;background-clip:text;color:transparent">Inteligencia Artificial</span>.</h1>
          <p>Tickets privados, respuestas IA, Knowledge Base, soporte multilingüe y escalado a staff, todo en un solo lugar.</p>
          <div class="hero-actions"><a class="btn" href="/auth/discord">🚀 Invitar al bot</a><a class="btn alt" href="#pricing">Ver precios</a></div>
          <div class="hero-trust"><span>✓ <b>Tickets automáticos</b></span><span>✓ <b>Gemini AI</b></span><span>✓ <b>Multilingüe</b></span><span>✓ <b>Escalado a staff</b></span></div>
        </div>
        <div class="visual-wrap">
          <div class="glow"></div>
          <div class="ticket-ui">
            <div class="ticket-top"><div class="ticket-title"><div class="ticket-icon">◉</div><div><strong>AI Support</strong><span>tu servidor · IA activa</span></div></div><div class="ticket-status">● ONLINE</div></div>
            <div style="display:grid;grid-template-columns:170px 1fr;gap:14px;padding:15px 6px">
              <div class="card" style="padding:14px;background:rgba(255,255,255,.025)">
                <div style="font-size:10px;color:#8e91a5;font-weight:900;text-transform:uppercase">Tickets automáticos</div>
                <div style="font-size:28px;font-weight:950;margin-top:7px">24/7</div>
                <div class="help">Sin intervención inicial</div>
              </div>
              <div style="display:flex;align-items:center;justify-content:center">
                <div style="position:relative;width:175px;height:175px;border-radius:50%;background:radial-gradient(circle at 48% 34%,#242437 0 34%,#11111c 35% 100%);border:1px solid rgba(142,130,255,.25);box-shadow:0 0 75px rgba(109,93,252,.28)">
                  <div style="position:absolute;left:28px;right:28px;top:28px;height:72px;border-radius:36px;background:linear-gradient(160deg,#e9e9f2,#999bb1);box-shadow:inset 0 -7px 12px rgba(0,0,0,.18)"></div>
                  <div style="position:absolute;top:52px;left:58px;width:16px;height:16px;border-radius:50%;background:#5fdcff;box-shadow:0 0 18px #5fdcff"></div>
                  <div style="position:absolute;top:52px;right:58px;width:16px;height:16px;border-radius:50%;background:#8e82ff;box-shadow:0 0 18px #8e82ff"></div>
                  <div style="position:absolute;left:47px;right:47px;bottom:29px;height:31px;border-radius:14px 14px 32px 32px;background:linear-gradient(180deg,#8e82ff,#5447e6)"></div>
                  <div style="position:absolute;left:83px;top:8px;width:8px;height:22px;border-radius:8px;background:#9da0b4"></div>
                  <div style="position:absolute;left:79px;top:2px;width:16px;height:16px;border-radius:50%;background:#44d8ff;box-shadow:0 0 17px #44d8ff"></div>
                </div>
              </div>
            </div>
            <div class="chat">
              <div class="chat-row"><div class="chat-avatar">U</div><div class="bubble">¿Cómo configuro el bot?</div></div>
              <div class="chat-row"><div class="chat-avatar">✦</div><div class="bubble ai"><strong>AI Support</strong><br>Usa /panel y completa la configuración del servidor.</div></div>
              <div class="chat-row me"><div class="bubble me">Necesito hablar con un humano.</div><div class="chat-avatar">U</div></div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="section-block"><div class="stats-strip">
      <div class="stat-block"><strong>+2.000</strong><span>Objetivo de servidores</span></div>
      <div class="stat-block"><strong>24/7</strong><span>Asistencia automática</span></div>
      <div class="stat-block"><strong>🌍</strong><span>Multilingüe</span></div>
      <div class="stat-block"><strong>⚡</strong><span>Escalado a staff</span></div>
    </div></section>

    <section class="section-block" id="features"><div class="section-head"><div><span class="pill">Funciones</span><h2>Todo en un mismo panel.</h2><p>Una experiencia simple para administradores y miembros.</p></div></div>
      <div class="grid">
        <article class="card feature-card"><div class="feature-icon">🎫</div><h3>Tickets automáticos</h3><p>Canales privados con acciones de cierre y atención humana.</p></article>
        <article class="card feature-card"><div class="feature-icon">✦</div><h3>IA con Gemini</h3><p>Respuestas contextualizadas por servidor y por ticket.</p></article>
        <article class="card feature-card"><div class="feature-icon">🌍</div><h3>Multilingüe</h3><p>Detecta y mantiene el idioma del usuario.</p></article>
        <article class="card feature-card"><div class="feature-icon">📚</div><h3>Knowledge Base</h3><p>Reglas, FAQ, procedimientos y documentación propia.</p></article>
        <article class="card feature-card"><div class="feature-icon">🛎️</div><h3>Escalado a staff</h3><p>Entrega el contexto al equipo humano cuando hace falta.</p></article>
        <article class="card feature-card"><div class="feature-icon">📊</div><h3>Dashboard</h3><p>Uso, tickets, plan y configuración por servidor.</p></article>
      </div>
    </section>

    <section class="section-block" id="pricing"><div class="section-head"><div><span class="pill">Precios</span><h2>Planes simples.</h2><p>Todos los límites actuales se aplican por servidor.</p></div></div>
      <div class="grid">${plans}</div>
    </section>

    <section class="section-block"><div class="card" style="padding:28px"><div class="section-head" style="margin:0"><div><span class="pill">Ready</span><h2>Empieza en minutos.</h2><p>Conecta Discord, configura tu Knowledge Base y abre el primer ticket.</p></div><a class="btn" href="/auth/discord">Entrar con Discord</a></div></div></section>
  `));
});


app.get("/onboarding", async (req, res) => {
  const session = await currentSession(req);
  if (!session) return res.send(htmlShell("Cómo funciona", `
    <div class="legal"><span class="pill">Primeros pasos</span><h1>Configura AI Support en 3 pasos.</h1><p>Conecta tu servidor, carga tus reglas y prueba el primer ticket desde el dashboard.</p>
      <div class="grid" style="margin-top:26px"><div class="card step-card"><div class="step-number">01</div><h3>Inicia sesión</h3><p>Autoriza AI Support con tu cuenta de Discord.</p></div><div class="card step-card"><div class="step-number">02</div><h3>Añade el bot</h3><p>Elige el servidor y añade AI Support con los permisos necesarios.</p></div><div class="card step-card"><div class="step-number">03</div><h3>Configura y prueba</h3><p>Define Knowledge Base, staff, categoría y abre un ticket de prueba.</p></div></div>
      <div class="hero-actions"><a class="btn" href="/auth/discord">Empezar con Discord</a><a class="btn alt" href="/terms">Términos</a></div>
    </div>
  `));

  const first = session.guilds[0];
  const firstLink = first ? (client.guilds.cache.has(first.id) ? "/servers/" + encodeURIComponent(first.id) : "/servers/" + encodeURIComponent(first.id) + "/install") : "/dashboard";
  const firstLabel = first ? (client.guilds.cache.has(first.id) ? "Abrir configuración" : "Añadir bot") : "Ver servidores";

  res.send(htmlShell("Primeros pasos", `
    <div class="dashboard-hero"><div><span class="pill">Onboarding</span><h1>Vamos a dejar tu servidor listo.</h1><p>Comprueba los tres pilares de una instalación limpia.</p></div><div class="dashboard-actions"><a class="btn" href="${firstLink}">${firstLabel}</a></div></div>
    <div class="grid"><div class="card step-card"><div class="step-number">01 · Cuenta</div><h3>Discord conectado</h3><p>Tu sesión está activa y puede gestionar los servidores permitidos.</p><div class="badge success" style="margin-top:14px">✓ Listo</div></div>
      <div class="card step-card"><div class="step-number">02 · Servidor</div><h3>${escapeHtml(first?.name || "Elige un servidor",100)}</h3><p>${first ? (client.guilds.cache.has(first.id) ? "El bot ya está conectado en este servidor." : "El bot todavía no está instalado en este servidor.") : "No hay servidores gestionables en esta cuenta."}</p></div>
      <div class="card step-card"><div class="step-number">03 · Knowledge Base</div><h3>Enseña a la IA tus reglas</h3><p>Añade normas, FAQ, procedimientos y otra documentación propia de tu comunidad.</p></div></div>
    <div class="card" style="margin-top:18px"><div class="notice"><strong>Prueba recomendada:</strong> guarda la configuración y abre un ticket de prueba antes de compartir el bot con toda la comunidad.</div></div>
  `, session.user));
});

app.get("/terms", (_req, res) => res.send(htmlShell("Términos de servicio", `
  <main class="legal"><span class="pill">Información legal</span><h1>Términos de servicio</h1><p>Última actualización: octubre de 2026</p>
  <h2>1. Servicio</h2><p>AI Support es una aplicación de automatización para comunidades de Discord que proporciona tickets privados, asistencia mediante IA, configuración por servidor y escalado a personal humano.</p>
  <h2>2. Cuenta y permisos</h2><p>Debes utilizar una cuenta de Discord con permisos suficientes para gestionar el servidor correspondiente. Eres responsable de mantener seguras tus credenciales y de revisar las autorizaciones que otorgas.</p>
  <h2>3. Uso aceptable</h2><p>No debes utilizar el servicio para actividades ilícitas, abusivas, fraudulentas, para intentar comprometer cuentas o sistemas de terceros, ni para eludir medidas de seguridad o límites.</p>
  <h2>4. IA y Knowledge Base</h2><p>Las respuestas generadas por IA pueden contener errores. Debes revisar las respuestas relevantes y mantener actualizada la documentación del servidor.</p>
  <h2>5. Planes y facturación</h2><p>Los planes de pago se aplican por servidor. Las condiciones de precio, renovación y cancelación se muestran durante la contratación y en el portal de facturación.</p>
  <h2>6. Disponibilidad</h2><p>No se garantiza disponibilidad ininterrumpida. El servicio también depende de Discord, proveedores de IA, Stripe y otros terceros.</p>
  <h2>7. Cambios</h2><p>Las condiciones pueden actualizarse para reflejar cambios del producto, obligaciones legales o mejoras operativas.</p>
  <h2>8. Información del titular</h2><p>Antes de publicar estas condiciones como documento legal definitivo, completa aquí los datos legales de la entidad titular, domicilio y canal de contacto.</p>
  </main>
`)));

app.get("/privacy", (_req, res) => res.send(htmlShell("Política de privacidad", `
  <main class="legal"><span class="pill">Privacidad</span><h1>Política de privacidad</h1><p>Última actualización: octubre de 2026</p>
  <h2>1. Datos tratados</h2><p>La aplicación puede tratar identificadores de Discord, nombre de usuario, servidores autorizables, configuración del servidor, tickets y métricas de uso necesarias para prestar el servicio.</p>
  <h2>2. Finalidades</h2><p>Los datos se utilizan para autenticar administradores, gestionar la configuración por servidor, mantener el historial de tickets, aplicar límites, procesar pagos cuando corresponda y mantener la seguridad.</p>
  <h2>3. Terceros</h2><p>Discord proporciona identidad y datos de servidor mediante OAuth; el proveedor de IA procesa las solicitudes necesarias para generar respuestas; Stripe procesa los pagos y la facturación contratada.</p>
  <h2>4. Conservación</h2><p>Los datos se conservan durante el tiempo necesario para prestar el servicio, resolver incidencias, mantener la seguridad y cumplir obligaciones legales o contractuales.</p>
  <h2>5. Seguridad</h2><p>La aplicación utiliza controles de sesión, cookies seguras, validación de origen, limitación de solicitudes y auditoría de acciones administrativas.</p>
  <h2>6. Derechos</h2><p>Antes de publicar esta política como documento legal definitivo, completa los datos del responsable del tratamiento, la base jurídica y el canal para ejercer derechos.</p>
  </main>
`)));


app.get("/pricing", async (req, res) => {
  const session = await currentSession(req);
  if (!session) return res.redirect("/");

  const guildId = cleanText(req.query.guild, 100).trim();
  if (!guildId) {
    const serverLinks = session.guilds.map(guild => {
      const icon = discordIconUrl(guild);
      return '<article class="card"><div class="server-card"><div class="server-icon">' +
        (icon ? '<img src="' + escapeHtml(icon,300) + '" alt="">' : '◎') +
        '</div><div class="server-meta"><div class="server-name">' + escapeHtml(guild.name,100) + '</div>' +
        '<div class="status">Gestionar facturación de este servidor</div></div>' +
        '<a class="btn btn-sm" href="/pricing?guild=' + encodeURIComponent(guild.id) + '">Ver planes</a></div></article>';
    }).join("");

    return res.send(htmlShell("Planes", `
      <div class="dashboard-hero"><div><span class="pill">Facturación</span><h1>Selecciona un servidor.</h1><p>Los planes se contratan por servidor de Discord, no por cuenta global.</p></div></div>
      <div class="grid">${serverLinks || '<div class="card empty" style="grid-column:1/-1"><div class="feature-icon">◈</div><h3>No hay servidores gestionables</h3><p>Conecta una cuenta con permisos de administración.</p></div>'}</div>
    `, session.user));
  }

  const guild = session.guilds.find(g => g.id === guildId);
  if (!guild) return res.status(403).send("No autorizado.");
  const pricingDiscordGuild = client.guilds.cache.get(guild.id);
  if (!await userCanManageGuild(pricingDiscordGuild, session.user.id)) return res.status(403).send("No autorizado.");

  const planState = await getGuildPlan(guild.id);
  const currentPlanKey = planState.status === "active" ? normalizePlan(planState.plan) : "free";
  const currentPlan = getPlanDefinition(currentPlanKey);
  const currentPlanBlock = currentPlanKey === "free"
    ? '<span class="badge muted">STARTER</span>'
    : '<span class="badge success">' + escapeHtml(currentPlan.name,30) + ' · ' + escapeHtml(planState.status,30) + '</span>';
  const portalButton = planState.stripeCustomerId
    ? '<a class="btn alt" href="/billing/portal/' + encodeURIComponent(guild.id) + '">Gestionar facturación</a>'
    : '';
  const canBuyPaid = currentPlanKey === "free";
  const proButton = canBuyPaid
    ? '<form method="post" action="/billing/checkout/' + encodeURIComponent(guild.id) + '/pro" style="margin:0"><button class="btn" type="submit">Contratar Pro · $6/mes</button></form>'
    : '<span class="badge muted">Plan ya activo</span>';
  const lifetimeButton = canBuyPaid
    ? '<form method="post" action="/billing/checkout/' + encodeURIComponent(guild.id) + '/lifetime" style="margin:0"><button class="btn" type="submit">Comprar Lifetime · $30</button></form>'
    : '<span class="badge muted">Plan ya activo</span>';

  const planCards = Object.values(PLAN_DEFINITIONS).map(def => {
    const priceSuffix = def.key === "pro" ? "<span>/mes</span>" : "";
    const featureRows = def.features.map(x => "<div>✓ " + escapeHtml(x,160) + "</div>").join("");
    const limits = "<div><b>" + formatLimit(def.ticketsPerMonth, "tickets nuevos/mes") + "</b></div>" +
      "<div><b>" + formatLimit(def.aiRepliesPerMonth, "respuestas IA/mes") + "</b></div>" +
      "<div><b>" + formatLimit(def.knowledgeChars, "caracteres KB") + "</b></div>";
    const action = def.key === "free" ? '<span class="badge muted">Incluido</span>' : (def.key === "pro" ? proButton : lifetimeButton);
    return '<article class="card price-card ' + (def.key === "pro" ? "featured" : "") + '">' +
      (def.key === "pro" ? '<div class="price-badge">MÁS USADO</div>' : '') +
      '<div class="price-name">' + escapeHtml(def.name,40) + '</div>' +
      '<div class="price-value">' + escapeHtml(def.price,20) + priceSuffix + '</div>' +
      '<p>' + escapeHtml(def.billing,80) + '.</p><div class="price-list">' + limits + featureRows + '</div>' +
      '<div class="actions" style="margin-top:auto">' + action + '</div></article>';
  }).join("");

  res.send(htmlShell("Planes", `
    <div class="dashboard-hero"><div><span class="pill">Facturación · ${escapeHtml(guild.name,100)}</span><h1>Elige tu plan.</h1><p>Los límites de uso y la facturación se aplican por servidor. Stripe gestiona los pagos.</p></div>
      <div class="dashboard-actions">${portalButton}<a class="btn alt" href="/servers/${encodeURIComponent(guild.id)}">← Panel</a></div>
    </div>
    <div class="card" style="margin-bottom:18px"><div class="toolbar"><div><span class="muted">Plan actual</span><div style="margin-top:5px;font-weight:900;font-size:18px">${escapeHtml(currentPlan.name,40)}</div></div><div>${currentPlanBlock}</div></div></div>
    <div class="grid">${planCards}</div>
    <div class="card" style="margin-top:18px"><div class="notice"><strong>Uso mensual:</strong> Lifetime no tiene renovación mensual, pero mantiene límites mensuales para proteger la estabilidad del servicio.</div></div>
  `, session.user));
});


app.post("/billing/checkout/:guildId/:plan", rateLimit("billing-checkout", 10, 10 * 60 * 1000), async (req, res) => {
  try {
    const session = await currentSession(req);
    if (!session) return res.redirect("/");

    const access = await requireManagedGuild(req, session);
    if (!access) return res.status(403).send("No autorizado.");
    const { guild, discordGuild } = access;

    const plan = String(req.params.plan || "").toLowerCase();
    if (!["pro", "lifetime"].includes(plan)) {
      return res.status(400).send("Plan no válido.");
    }

    if (!stripe) {
      return res.status(503).send(htmlShell("Stripe no configurado",
        "<div class=\"card\"><h2>⚠️ Falta Stripe</h2><p class=\"muted\">Añade STRIPE_SECRET_KEY en Railway. El secreto nunca se guarda en GitHub.</p><a class=\"btn alt\" href=\"/pricing?guild=" + encodeURIComponent(guild.id) + "\">Volver</a></div>",
        session.user
      ));
    }

    const current = await getGuildPlan(guild.id);
    if (current.plan !== "free") {
      return res.status(409).send(htmlShell("Plan activo",
        "<div class=\"card\"><h2>Plan ya activo</h2><p class=\"muted\">Este servidor ya tiene el plan " + escapeHtml(String(current.plan),30) + " (" + escapeHtml(String(current.status),30) + ").</p><div class=\"actions\">" +
        (current.stripeCustomerId ? "<a class=\"btn\" href=\"/billing/portal/" + encodeURIComponent(guild.id) + "\">Gestionar facturación</a>" : "") +
        "<a class=\"btn alt\" href=\"/servers/" + encodeURIComponent(guild.id) + "\">Volver</a></div></div>",
        session.user
      ));
    }

    const priceId = plan === "pro" ? config.stripeProPriceId : config.stripeLifetimePriceId;
    if (!priceId) {
      return res.status(503).send(htmlShell("Precio no configurado",
        "<div class=\"card\"><h2>⚠️ Falta la configuración del precio</h2><p class=\"muted\">Configura el Price ID correspondiente en Railway.</p></div>",
        session.user
      ));
    }

    const metadata = {
      guild_id: guild.id,
      discord_user_id: session.user.id,
      plan
    };

    const checkout = await stripe.checkout.sessions.create({
      mode: plan === "pro" ? "subscription" : "payment",
      client_reference_id: guild.id,
      line_items: [{ price: priceId, quantity: 1 }],
      metadata,
      allow_promotion_codes: true,
      success_url: config.dashboardUrl + "/servers/" + encodeURIComponent(guild.id) + "?billing=success",
      cancel_url: config.dashboardUrl + "/pricing?guild=" + encodeURIComponent(guild.id) + "&billing=cancel",
      ...(plan === "pro" ? { subscription_data: { metadata } } : {}),
      ...(current.stripeCustomerId ? { customer: current.stripeCustomerId } : {})
    });

    if (!checkout.url) throw new Error("Stripe no devolvió una URL de Checkout.");
    return res.redirect(303, checkout.url);
  } catch (error) {
    console.error("Stripe checkout error:", error);
    const session = await currentSession(req);
    return res.status(500).send(htmlShell("Error de facturación",
      "<div class=\"card\"><h2>⚠️ No se pudo abrir Stripe Checkout</h2><p class=\"error\">" + escapeHtml(error.message,1000) + "</p><a class=\"btn alt\" href=\"/pricing?guild=" + encodeURIComponent(req.params.guildId || "") + "\">Volver</a></div>",
      session?.user || null
    ));
  }
});

app.get("/billing/portal/:guildId", rateLimit("billing-portal", 20, 10 * 60 * 1000), async (req, res) => {
  try {
    const session = await currentSession(req);
    if (!session) return res.redirect("/");

    const guild = session.guilds.find(g => g.id === req.params.guildId);
    if (!guild) return res.status(403).send("No autorizado.");

    if (!stripe) return res.status(503).send("Stripe no está configurado.");

    const plan = await getGuildPlan(guild.id);
    if (!plan.stripeCustomerId) {
      return res.status(404).send("Este servidor todavía no tiene una cuenta de facturación.");
    }

    const portal = await stripe.billingPortal.sessions.create({
      customer: plan.stripeCustomerId,
      return_url: config.dashboardUrl + "/servers/" + encodeURIComponent(guild.id)
    });

    return res.redirect(303, portal.url);
  } catch (error) {
    console.error("Stripe portal error:", error);
    return res.status(500).send("No se pudo abrir el portal de facturación.");
  }
});

app.post("/api/stripe/webhook", async (req, res) => {
  if (!stripe || !config.stripeWebhookSecret) {
    return res.status(503).send("Stripe webhook no configurado.");
  }

  const signature = req.headers["stripe-signature"];
  if (!signature || !req.rawBody) {
    return res.status(400).send("Firma Stripe ausente.");
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.rawBody, signature, config.stripeWebhookSecret);
  } catch (error) {
    console.error("Stripe webhook signature error:", error.message);
    return res.status(400).send("Webhook signature inválida.");
  }

  try {
    const object = event.data.object;

    if (event.type === "checkout.session.completed") {
      const guildId = object.metadata?.guild_id;
      const plan = object.metadata?.plan;
      if (guildId && ["pro", "lifetime"].includes(plan)) {
        await saveGuildSubscription({
          guildId,
          plan,
          status: "active",
          stripeCustomerId: typeof object.customer === "string" ? object.customer : null,
          stripeSubscriptionId: typeof object.subscription === "string" ? object.subscription : null,
          stripePriceId: plan === "pro" ? config.stripeProPriceId : config.stripeLifetimePriceId
        });
      }
    }

    if (event.type === "customer.subscription.updated") {
      const guildId = object.metadata?.guild_id;
      if (guildId) {
        const subscriptionStatus = String(object.status || "active");
        const normalizedStatus = ["active", "trialing"].includes(subscriptionStatus) ? "active" : subscriptionStatus;
        await saveGuildSubscription({
          guildId,
          plan: "pro",
          status: normalizedStatus,
          stripeCustomerId: typeof object.customer === "string" ? object.customer : null,
          stripeSubscriptionId: object.id,
          stripePriceId: object.items?.data?.[0]?.price?.id || config.stripeProPriceId
        });
      }
    }

    if (event.type === "customer.subscription.deleted") {
      const guildId = object.metadata?.guild_id;
      if (guildId) {
        await saveGuildSubscription({
          guildId,
          plan: "free",
          status: "canceled",
          stripeCustomerId: typeof object.customer === "string" ? object.customer : null,
          stripeSubscriptionId: null,
          stripePriceId: null
        });
      }
    }

    return res.json({ received: true });
  } catch (error) {
    console.error("Stripe webhook processing error:", error);
    return res.status(500).send("Webhook processing error.");
  }
});

app.get("/servers/:guildId/install", async (req, res) => {
  const session = await currentSession(req);
  if (!session) return res.redirect("/");
  const guild = session.guilds.find(g => g.id === req.params.guildId);
  if (!guild) return res.status(403).send("No autorizado.");

  const params = new URLSearchParams({
    client_id: config.clientId,
    scope: "bot applications.commands",
    permissions: BOT_PERMISSIONS,
    guild_id: guild.id,
    disable_guild_select: "true"
  });

  res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
});


app.get("/admin", async (req, res) => {
  try {
    const session = await currentSession(req);
    if (!session) return res.redirect("/");
    if (!isFounder(session)) return res.status(403).send(htmlShell("No autorizado", '<div class="card"><h2>403 · No autorizado</h2><p class="muted">Este panel está reservado al administrador principal del SaaS.</p><a class="btn alt" href="/dashboard">Volver</a></div>', session.user));

    const [stats, codes, auditLogs] = await Promise.all([getActivationCodeStats(), listActivationCodes(100), getRecentAuditLogs(50)]);
    const rows=codes.map(code=>{
      const s=String(code.status||"").toLowerCase();
      const cls=s==="available"?"success":s==="used"?"muted":"warning";
      const label=s==="available"?"Disponible":s==="used"?"Usado":s==="expired"?"Caducado":"Desactivado";
      return '<tr><td><strong>' + escapeHtml(code.code_hint,40) + '••••</strong></td><td>' + escapeHtml(getPlanDefinition(normalizePlan(code.plan)).name,40) + '</td><td><span class="badge ' + cls + '">' + label + '</span></td><td>' + escapeHtml(formatDate(code.created_at),80) + '</td><td>' + escapeHtml(formatDate(code.expires_at),80) + '</td><td>' + escapeHtml(code.redeemed_guild_id || "—",80) + '</td></tr>';
    }).join("");
    const audits=auditLogs.map(log=>'<tr><td>'+escapeHtml(formatDate(log.created_at),80)+'</td><td><strong>'+escapeHtml(log.action,100)+'</strong></td><td>'+escapeHtml(log.actor_discord_user_id,80)+'</td><td>'+escapeHtml(log.guild_id||"—",80)+'</td></tr>').join("");

    const notice = req.query.generated === "1" ? '<div class="notice success" style="margin-bottom:14px"><strong>✓ Lote generado.</strong> Los códigos completos se muestran solo una vez.</div>' :
      req.query.disabled === "1" ? '<div class="notice success" style="margin-bottom:14px"><strong>✓ Código desactivado.</strong></div>' :
      req.query.disabled === "0" ? '<div class="notice" style="margin-bottom:14px;border-color:rgba(255,113,138,.2);background:rgba(255,113,138,.06);color:#ffc3cb"><strong>⚠️ No se encontró un código disponible.</strong></div>' : "";

    res.send(htmlShell("Admin · AI Support", `
      <div class="admin-layout fade-in">
        <aside class="admin-sidebar">
          <div class="admin-title">✦ Admin</div>
          <a class="side-link active" href="/admin"><span class="icon">⌁</span>Códigos de activación</a>
          <a class="side-link" href="#activity"><span class="icon">◌</span>Actividad</a>
          <a class="side-link" href="#audit"><span class="icon">◫</span>Logs de auditoría</a>
          <a class="side-link" href="/dashboard"><span class="icon">⌂</span>Dashboard</a>
        </aside>
        <main class="app-main">
          <div class="page-top"><div><span class="pill">Administración segura</span><h1>Códigos de activación.</h1><p>Genera y gestiona licencias Pro y Lifetime del SaaS.</p></div><div class="dashboard-actions"><a class="btn alt btn-sm" href="/dashboard">← Dashboard</a></div></div>
          ${notice}
          <div class="metric-grid">
            <div class="metric-card"><div class="metric-top"><span>Códigos totales</span><span class="metric-icon">▣</span></div><div class="metric-value">${stats.total}</div></div>
            <div class="metric-card"><div class="metric-top"><span>Disponibles</span><span class="metric-icon">✓</span></div><div class="metric-value">${stats.available}</div></div>
            <div class="metric-card"><div class="metric-top"><span>Usados / caducados</span><span class="metric-icon">◈</span></div><div class="metric-value">${stats.used + stats.disabledOrExpired}</div></div>
          </div>

          <section class="section-block" style="padding-bottom:0">
            <div class="two-col">
              <div class="panel-card"><div class="section-head"><div><span class="pill">Generador</span><h2>Generar códigos.</h2><p>Crea un lote seguro en el servidor.</p></div></div>
                <form method="post" action="/admin/activation-codes/generate">
                  <div class="form-grid">
                    <div class="field"><label>Plan</label><select name="plan"><option value="pro">Pro · $6/mes</option><option value="lifetime">Lifetime · $30</option></select></div>
                    <div class="field"><label>Cantidad</label><select name="quantity"><option>1</option><option>10</option><option>50</option><option>100</option></select></div>
                    <div class="field full"><label>Caducidad opcional</label><input type="datetime-local" name="expiresAt"><div class="help">Máximo 100 por lote.</div></div>
                  </div>
                  <button class="btn" style="margin-top:16px" type="submit">🪙 Generar códigos</button>
                </form>
              </div>
              <div class="panel-card"><div class="section-head"><div><span class="pill">Estado</span><h2>Licencias.</h2><p>Resumen del inventario actual.</p></div></div>
                <div class="grid" style="grid-template-columns:1fr 1fr"><div class="card"><div class="stat-label">Pro</div><div class="kpi" style="font-size:28px">✓</div><div class="help">Disponible bajo demanda</div></div><div class="card"><div class="stat-label">Lifetime</div><div class="kpi" style="font-size:28px">✓</div><div class="help">Pago único</div></div></div>
              </div>
            </div>
          </section>

          <section class="section-block" id="activity"><div class="section-head"><div><span class="pill">Actividad</span><h2>Códigos generados.</h2><p>Los códigos completos no se vuelven a mostrar después de generarlos.</p></div></div><div class="panel-card">${rows ? '<div class="table-wrap"><table><thead><tr><th>Código</th><th>Plan</th><th>Estado</th><th>Creado</th><th>Expira</th><th>Servidor</th></tr></thead><tbody>'+rows+'</tbody></table></div>' : '<div class="empty"><div class="feature-icon">⌁</div><h3>No hay códigos</h3><p>Genera tu primer lote.</p></div>'}</div></section>

          <section class="section-block"><div class="section-head"><div><span class="pill">Seguridad</span><h2>Invalidar un código.</h2><p>Solo códigos disponibles.</p></div></div><div class="panel-card"><form method="post" action="/admin/activation-codes/disable"><div class="code-box"><input name="code" maxlength="32" autocomplete="off" placeholder="Pega aquí el código completo" required><button class="btn danger" type="submit">Desactivar</button></div></form><div class="help" style="margin-top:9px">Los códigos completos no se almacenan en texto plano.</div></div></section>

          <section class="section-block" id="audit"><div class="section-head"><div><span class="pill">Auditoría</span><h2>Registro de seguridad.</h2><p>Últimas 50 acciones administrativas.</p></div></div><div class="panel-card">${audits ? '<div class="table-wrap"><table><thead><tr><th>Fecha</th><th>Acción</th><th>Usuario</th><th>Servidor</th></tr></thead><tbody>'+audits+'</tbody></table></div>' : '<p class="muted">Sin actividad.</p>'}</div></section>
        </main>
      </div>
    `, session.user));
  } catch (error) {
    console.error("Admin dashboard error:", error);
    res.status(500).send(htmlShell("Error", '<div class="card"><h2>⚠️ Error en administración</h2><p class="error">' + escapeHtml(error.message,1000) + '</p><a class="btn alt" href="/dashboard">Volver</a></div>', (await currentSession(req))?.user || null));
  }
});


app.post("/admin/activation-codes/generate", rateLimit("admin-code-generate", 10, 60 * 60 * 1000), async (req, res) => {
  try {
    const session = await currentSession(req);
    if (!session) return res.redirect("/");
    if (!isFounder(session)) return res.status(403).send("No autorizado.");

    const plan = String(req.body?.plan || "").toLowerCase();
    const quantity = Number(req.body?.quantity || 0);
    const expiresAt = cleanText(req.body?.expiresAt, 80).trim() || null;

    if (!["pro", "lifetime"].includes(plan)) return res.status(400).send("Plan no válido.");

    const codes = await createActivationCodes({ plan, quantity, expiresAt, createdByDiscordUserId: session.user.id });
    await recordAuditLog({ actorDiscordUserId: session.user.id, action: "activation_codes_generated", details: { plan, quantity: codes.length, expiresAt } });

    const codeText = codes.join("\n");
    const downloadHref = "data:text/plain;charset=utf-8," + encodeURIComponent(codeText);
    res.setHeader("Cache-Control", "no-store, private");

    res.send(htmlShell("Códigos generados", `
      <div class="page-top"><div><span class="pill">✓ Lote creado</span><h1>Códigos listos.</h1><p>${codes.length} licencia(s) ${escapeHtml(getPlanDefinition(plan).name,40)} generadas. Esta es la única pantalla donde se muestran completas.</p></div><div class="dashboard-actions"><a class="btn alt btn-sm" href="/admin">← Admin</a></div></div>
      <div class="panel-card">
        <label>Códigos completos</label>
        <textarea id="generated-codes" readonly style="min-height:330px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.04em">${escapeHtml(codeText,10000)}</textarea>
        <div class="actions" style="margin-top:14px"><button class="btn" type="button" onclick="navigator.clipboard.writeText(document.getElementById('generated-codes').value)">📋 Copiar todos</button><a class="btn alt" href="${escapeHtml(downloadHref,20000)}" download="activation-codes-${escapeHtml(plan,20)}.txt">⬇️ Descargar TXT</a></div>
        <div class="notice" style="margin-top:14px">Guárdalos ahora. Por seguridad, no volverán a aparecer completos en el panel de administración.</div>
      </div>
    `, session.user));
  } catch (error) {
    console.error("Activation code generation error:", error);
    res.status(400).send(htmlShell("Error", '<div class="card"><h2>⚠️ No se pudieron generar los códigos</h2><p class="error">' + escapeHtml(error.message,1000) + '</p><a class="btn alt" href="/admin">Volver</a></div>', (await currentSession(req))?.user || null));
  }
});


app.post("/admin/activation-codes/disable", rateLimit("admin-code-disable", 30, 60 * 60 * 1000), async (req, res) => {
  try {
    const session = await currentSession(req);
    if (!session) return res.redirect("/");
    if (!isFounder(session)) return res.status(403).send("No autorizado.");

    const submittedCode = cleanText(req.body?.code, 32).trim();
    const disabled = await disableActivationCode(submittedCode);

    if (disabled) {
      await recordAuditLog({
        actorDiscordUserId: session.user.id,
        action: "activation_code_disabled",
        details: { codeHint: submittedCode.split("-").slice(0, 2).join("-") }
      });
    }

    return res.redirect("/admin?disabled=" + (disabled ? "1" : "0"));
  } catch (error) {
    console.error("Activation code disable error:", error);
    res.status(500).send("No se pudo desactivar el código.");
  }
});

app.post("/api/servers/:guildId/activation-code", rateLimit("activation-redeem", 10, 5 * 60 * 1000), async (req, res) => {
  try {
    const session = await currentSession(req);
    if (!session) return res.status(401).send("Sesión requerida.");

    const access = await requireManagedGuild(req, session);
    if (!access) {
      return res.status(403).send("No autorizado.");
    }
    const { guild } = access;

    const code = cleanText(req.body?.code, 32).trim();
    if (!code) return res.redirect("/servers/" + encodeURIComponent(guild.id) + "?activation=invalid#activation");

    const result = await redeemActivationCode({
      code,
      guildId: guild.id,
      discordUserId: session.user.id
    });

    if (result.ok) {
      await recordAuditLog({
        actorDiscordUserId: session.user.id,
        action: "activation_code_redeemed",
        guildId: guild.id,
        details: { plan: result.plan }
      });
      return res.redirect(
        "/servers/" + encodeURIComponent(guild.id) +
        "?activation=success&plan=" + encodeURIComponent(result.plan) + "#activation"
      );
    }

    return res.redirect(
      "/servers/" + encodeURIComponent(guild.id) +
      "?activation=" + encodeURIComponent(result.reason) + "#activation"
    );
  } catch (error) {
    console.error("Activation code redeem route error:", error);
    return res.redirect("/servers/" + encodeURIComponent(req.params.guildId) + "?activation=error#activation");
  }
});

app.get("/dashboard", async (req, res) => {
  const session = await currentSession(req);
  if (!session) return res.redirect("/");

  const connectedGuild = session.guilds.find(g => client.guilds.cache.has(g.id)) || session.guilds[0] || null;
  let stats = { totalTickets:0, openTickets:0, closedTickets:0, escalatedTickets:0, totalMessages:0 };
  let usage = { ticketsCreated:0, aiResponses:0 };
  let plan = { plan:"free", status:"active" };
  let definition = getPlanDefinition("free");

  if (connectedGuild) {
    try {
      [stats, usage, plan] = await Promise.all([
        getGuildDashboardStats(connectedGuild.id),
        getGuildUsage(connectedGuild.id),
        getGuildPlan(connectedGuild.id)
      ]);
      definition = getPlanDefinition(plan.status === "active" ? normalizePlan(plan.plan) : "free");
    } catch (error) {
      console.warn("[DASHBOARD] No se pudieron cargar métricas:", error.message);
    }
  }

  const ticketPct = Math.min(100, Math.round((usage.ticketsCreated / Math.max(1, definition.ticketsPerMonth)) * 100));
  const aiPct = Math.min(100, Math.round((usage.aiResponses / Math.max(1, definition.aiRepliesPerMonth)) * 100));
  const closeBase = Math.max(1, stats.totalTickets);
  const openPct = Math.round(stats.openTickets / closeBase * 100);
  const closedPct = Math.round(stats.closedTickets / closeBase * 100);
  const escalatedPct = Math.round(stats.escalatedTickets / closeBase * 100);
  const serverIcon = connectedGuild ? discordIconUrl(connectedGuild) : "";

  const serverOptions = session.guilds.map(g => '<option value="' + escapeHtml(g.id,80) + '"' + (connectedGuild && g.id === connectedGuild.id ? ' selected' : '') + '>' + escapeHtml(g.name,100) + '</option>').join("");
  const serverCards = session.guilds.map(g => {
    const inBot = client.guilds.cache.has(g.id);
    const icon = discordIconUrl(g);
    return '<a class="card" href="' + (inBot ? '/servers/' + encodeURIComponent(g.id) : '/servers/' + encodeURIComponent(g.id) + '/install') + '">' +
      '<div class="server-card"><div class="server-icon">' + (icon ? '<img src="' + escapeHtml(icon,300) + '" alt="">' : '◎') + '</div>' +
      '<div class="server-meta"><div class="server-name">' + escapeHtml(g.name,100) + '</div><div class="status"><span class="status-dot ' + (inBot ? 'online' : 'offline') + '"></span>' + (inBot ? 'Bot conectado' : 'Pendiente de instalar') + '</div></div>' +
      '<span class="btn btn-sm ' + (inBot ? '' : 'alt') + '">' + (inBot ? 'Abrir' : 'Añadir') + '</span></div></a>';
  }).join("");

  res.send(htmlShell("Dashboard", `
    <div class="app-shell fade-in">
      <aside class="app-sidebar">
        <div class="server-switch">
          <div class="mini-icon">${serverIcon ? '<img src="' + escapeHtml(serverIcon,300) + '" alt="">' : '◎'}</div>
          <div class="name"><strong>${escapeHtml(connectedGuild?.name || "Mi servidor",100)}</strong><span>${connectedGuild ? "Servidor seleccionado" : "Sin servidor"}</span></div>
          <span>⌄</span>
        </div>
        <div class="side-group">Workspace</div>
        <a class="side-link active" href="/dashboard"><span class="icon">⌂</span>Inicio</a>
        <a class="side-link" href="#servers"><span class="icon">◈</span>Servidores</a>
        <a class="side-link" href="${connectedGuild ? '/servers/' + encodeURIComponent(connectedGuild.id) + '#tickets' : '#servers'}"><span class="icon">▣</span>Tickets</a>
        <a class="side-link" href="${connectedGuild ? '/servers/' + encodeURIComponent(connectedGuild.id) + '#ai' : '#servers'}"><span class="icon">✦</span>IA</a>
        <a class="side-link" href="${connectedGuild ? '/servers/' + encodeURIComponent(connectedGuild.id) + '#knowledge' : '#servers'}"><span class="icon">▤</span>Knowledge Base</a>
        <a class="side-link" href="${connectedGuild ? '/servers/' + encodeURIComponent(connectedGuild.id) + '#staff' : '#servers'}"><span class="icon">♙</span>Configuración</a>
        <a class="side-link" href="${connectedGuild ? '/pricing?guild=' + encodeURIComponent(connectedGuild.id) : '/pricing'}"><span class="icon">◈</span>Facturación</a>
        <a class="side-link" href="${connectedGuild ? '/servers/' + encodeURIComponent(connectedGuild.id) + '#activation' : '#servers'}"><span class="icon">⌁</span>Código de activación</a>
      </aside>

      <main class="app-main">
        <div class="page-top">
          <div><span class="pill">Dashboard principal</span><h1>Hola, ${escapeHtml(session.user.username,80)} 👋</h1><p>Gestiona tu bot y tu soporte desde aquí.</p></div>
          <div class="dashboard-actions"><a class="btn btn-sm" href="/onboarding">🚀 Primeros pasos</a><a class="btn alt btn-sm" href="/pricing">Ver planes</a></div>
        </div>

        ${connectedGuild ? '<div class="profile-banner"><div><strong>' + escapeHtml(connectedGuild.name,100) + '</strong><div class="help">Métricas del servidor seleccionado · datos actuales</div></div><div class="badge success">● BOT ONLINE</div></div>' : ''}

        <div class="metric-grid">
          <div class="metric-card"><div class="metric-top"><span>Tickets este mes</span><span class="metric-icon">▣</span></div><div class="metric-value">${usage.ticketsCreated} <span style="font-size:13px;color:var(--muted)">/ ${definition.ticketsPerMonth}</span></div><div class="progress" style="margin-top:10px"><span style="width:${ticketPct}%"></span></div><div class="metric-sub">${ticketPct}% del límite actual</div></div>
          <div class="metric-card"><div class="metric-top"><span>Respuestas IA</span><span class="metric-icon">✦</span></div><div class="metric-value">${usage.aiResponses} <span style="font-size:13px;color:var(--muted)">/ ${definition.aiRepliesPerMonth}</span></div><div class="progress" style="margin-top:10px"><span style="width:${aiPct}%"></span></div><div class="metric-sub">${aiPct}% del límite actual</div></div>
          <div class="metric-card"><div class="metric-top"><span>Plan actual</span><span class="metric-icon">♛</span></div><div class="metric-value" style="font-size:25px">${escapeHtml(definition.name,40)}</div><div class="metric-sub">${escapeHtml(definition.price + " · " + definition.billing,60)}</div><a class="btn btn-sm" style="margin-top:13px" href="${connectedGuild ? '/pricing?guild=' + encodeURIComponent(connectedGuild.id) : '/pricing'}">Gestionar plan</a></div>
        </div>

        <section class="section-block" style="padding-bottom:0">
          <div class="two-col">
            <div class="panel-card">
              <div class="section-head" style="margin-bottom:3px"><div><span class="pill">Actividad</span><h2>Actividad de tickets</h2><p>Visualización del estado actual del soporte.</p></div><span class="pill">Último ciclo</span></div>
              <div class="activity-bars">
                <div class="activity-bar" style="height:${Math.max(18, Math.min(86, 20 + (stats.openTickets * 7)))}%"></div>
                <div class="activity-bar" style="height:${Math.max(25, Math.min(91, 18 + (stats.closedTickets * 5)))}%"></div>
                <div class="activity-bar" style="height:${Math.max(14, Math.min(80, 16 + (stats.totalTickets * 4)))}%"></div>
                <div class="activity-bar" style="height:${Math.max(24, Math.min(95, 24 + (stats.totalMessages % 60)))}%"></div>
                <div class="activity-bar" style="height:${Math.max(20, Math.min(88, 20 + (stats.escalatedTickets * 9)))}%"></div>
                <div class="activity-bar" style="height:${Math.max(18, Math.min(92, 26 + (usage.ticketsCreated * 3)))}%"></div>
                <div class="activity-bar" style="height:${Math.max(22, Math.min(96, 28 + (usage.aiResponses % 70)))}%"></div>
              </div>
              <div class="activity-axis"><span>Inicio</span><span>Actual</span></div>
            </div>
            <div class="panel-card">
              <div class="section-head" style="margin-bottom:12px"><div><span class="pill">Distribución</span><h2>Tipos / estado</h2></div></div>
              <div class="donut-wrap">
                <div class="donut"></div>
                <div class="legend">
                  <div class="legend-row"><span><span class="legend-dot"></span>Abiertos</span><b>${openPct}%</b></div>
                  <div class="legend-row"><span><span class="legend-dot"></span>Cerrados</span><b>${closedPct}%</b></div>
                  <div class="legend-row"><span><span class="legend-dot"></span>Escalados</span><b>${escalatedPct}%</b></div>
                  <div class="legend-row"><span><span class="legend-dot"></span>Total</span><b>${stats.totalTickets}</b></div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section class="section-block" id="servers"><div class="section-head"><div><span class="pill">Servidores</span><h2>Tus servidores.</h2><p>Selecciona dónde quieres trabajar.</p></div></div><div class="grid">${serverCards || '<div class="card empty" style="grid-column:1/-1"><div class="feature-icon">☁️</div><h3>No hay servidores gestionables</h3><p>Autoriza una cuenta de Discord con permisos suficientes.</p></div>'}</div></section>
      </main>
    </div>
  `, session.user));
});


app.get("/servers/:guildId", async (req, res) => {
  try {
    const session = await currentSession(req);
    if (!session) return res.redirect("/");
    const access = await requireManagedGuild(req, session);
    if (!access) return res.status(403).send("No autorizado.");

    const { guild, discordGuild } = access;
    const [cfg, stats, recentTickets, plan, usage] = await Promise.all([
      getGuildConfig(guild.id),
      getGuildDashboardStats(guild.id),
      getRecentGuildTickets(guild.id, 10),
      getGuildPlan(guild.id),
      getGuildUsage(guild.id)
    ]);

    const planKey = plan.status === "active" ? normalizePlan(plan.plan) : "free";
    const definition = getPlanDefinition(planKey);
    const icon = discordIconUrl(guild);
    const ticketPct = Math.min(100, Math.round((usage.ticketsCreated / Math.max(1, definition.ticketsPerMonth)) * 100));
    const aiPct = Math.min(100, Math.round((usage.aiResponses / Math.max(1, definition.aiRepliesPerMonth)) * 100));
    const categories = discordGuild.channels.cache.filter(ch => ch.type === 4).sort((a,b)=>a.position-b.position)
      .map(ch => '<option value="' + escapeHtml(ch.id,80) + '"' + (cfg.ticketCategoryId === ch.id ? ' selected' : '') + '>' + escapeHtml(ch.name,100) + '</option>').join("");
    const roles = Array.from(discordGuild.roles.cache.filter(r => r.id !== discordGuild.id && !r.managed).values()).sort((a,b)=>b.position-a.position).slice(0,100)
      .map(role => '<option value="' + escapeHtml(role.id,80) + '"' + (cfg.staffRoleId === role.id ? ' selected' : '') + '>' + escapeHtml(role.name,100) + '</option>').join("");

    const activationState = cleanText(req.query.activation,30).trim().toLowerCase();
    const activationPlan = normalizePlan(cleanText(req.query.plan,30).trim());
    const savedNotice = req.query.saved === "1" ? '<div class="notice success" style="margin-bottom:14px"><strong>✓ Cambios guardados.</strong> La configuración se ha actualizado.</div>' : "";
    const activationNotice = activationState === "success"
      ? '<div class="notice success"><strong>✓ Código activado.</strong> El servidor ahora tiene el plan ' + escapeHtml(getPlanDefinition(activationPlan).name,40) + '.</div>'
      : activationState
        ? '<div class="notice" style="border-color:rgba(255,113,138,.25);background:rgba(255,113,138,.06);color:#ffc3cb"><strong>⚠️ No se activó.</strong> ' + escapeHtml(activationReasonMessage(activationState),300) + '</div>'
        : "";

    const rows = recentTickets.map(t => {
      const channel = discordGuild.channels.cache.get(t.channel_id);
      return '<tr><td><strong>' + escapeHtml(channel?.name || t.channel_id,100) + '</strong></td><td>' + escapeHtml(t.owner_id,80) + '</td><td>' +
        (t.status === "open" ? '<span class="badge success">Abierto</span>' : '<span class="badge muted">Cerrado</span>') +
        '</td><td>' + (t.escalated ? '<span class="badge warning">Escalado</span>' : '<span class="badge muted">Normal</span>') +
        '</td><td>' + escapeHtml(formatDate(t.created_at),80) + '</td><td>' +
        (channel ? '<a class="btn ghost btn-sm" href="' + escapeHtml(channel.url,400) + '" target="_blank" rel="noopener">Discord</a>' : '—') + '</td></tr>';
    }).join("");

    res.send(htmlShell("Servidor · " + guild.name, `
      <div class="app-shell fade-in">
        <aside class="app-sidebar">
          <div class="server-switch"><div class="mini-icon">${icon ? '<img src="' + escapeHtml(icon,300) + '" alt="">' : '◎'}</div><div class="name"><strong>${escapeHtml(guild.name,100)}</strong><span>Servidor actual</span></div><span>⌄</span></div>
          <div class="side-group">Workspace</div>
          <a class="side-link" href="/dashboard"><span class="icon">⌂</span>Inicio</a>
          <a class="side-link" href="#overview"><span class="icon">◈</span>Resumen</a>
          <a class="side-link active" href="#tickets"><span class="icon">▣</span>Tickets</a>
          <a class="side-link" href="#ai"><span class="icon">✦</span>IA</a>
          <a class="side-link" href="#knowledge"><span class="icon">▤</span>Knowledge Base</a>
          <a class="side-link" href="#staff"><span class="icon">♙</span>Configuración</a>
          <a class="side-link" href="#billing"><span class="icon">◈</span>Facturación</a>
          <a class="side-link" href="#activation"><span class="icon">⌁</span>Código de activación</a>
        </aside>

        <main class="app-main">
          <div class="page-top"><div><span class="pill">${icon ? '<img src="' + escapeHtml(icon,200) + '" style="width:18px;height:18px;border-radius:6px;vertical-align:-4px;margin-right:6px" alt="">' : ''}${escapeHtml(guild.name,100)}</span><h1>Configuración.</h1><p>Personaliza el bot para este servidor y controla el soporte.</p></div><div class="dashboard-actions"><a class="btn alt btn-sm" href="/dashboard">← Dashboard</a><a class="btn btn-sm" href="/pricing?guild=${encodeURIComponent(guild.id)}">💳 Plan</a></div></div>
          ${savedNotice}

          <section id="overview" class="section" style="scroll-margin-top:100px">
            <div class="metric-grid">
              <div class="metric-card"><div class="metric-top"><span>Tickets totales</span><span class="metric-icon">▣</span></div><div class="metric-value">${stats.totalTickets}</div><div class="metric-sub">${stats.openTickets} abiertos · ${stats.closedTickets} cerrados</div></div>
              <div class="metric-card"><div class="metric-top"><span>Respuestas IA</span><span class="metric-icon">✦</span></div><div class="metric-value">${usage.aiResponses} <span style="font-size:12px;color:var(--muted)">/ ${definition.aiRepliesPerMonth}</span></div><div class="progress" style="margin-top:9px"><span style="width:${aiPct}%"></span></div></div>
              <div class="metric-card"><div class="metric-top"><span>Plan actual</span><span class="metric-icon">♛</span></div><div class="metric-value" style="font-size:25px">${escapeHtml(definition.name,40)}</div><div class="metric-sub">${escapeHtml(definition.price + " · " + definition.billing,60)}</div></div>
            </div>
          </section>

          <section id="tickets" class="section" style="margin-top:22px">
            <div class="section-head"><div><span class="pill">Tickets</span><h2>Conversaciones recientes.</h2><p>Últimos 10 tickets registrados.</p></div><span class="pill">${stats.openTickets} abiertos</span></div>
            <div class="panel-card">${rows ? '<div class="table-wrap"><table><thead><tr><th>Canal</th><th>Usuario</th><th>Estado</th><th>Escalado</th><th>Creado</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>' : '<div class="empty"><div class="feature-icon">▣</div><h3>No hay tickets todavía</h3><p>Abre un ticket en Discord para verlo aquí.</p></div>'}</div>
          </section>

          <section id="staff" class="section" style="margin-top:22px">
            <div class="section-head"><div><span class="pill">Configuración</span><h2>Personaliza tu servidor.</h2><p>La interfaz sigue la estructura del panel del mockup.</p></div></div>
            <form method="post" action="/api/servers/${encodeURIComponent(guild.id)}">
              <div class="form-section">
                <div class="tabbar" role="tablist">
                  <button class="tab-btn active" type="button" data-tab="general">General</button>
                  <button class="tab-btn" type="button" data-tab="tickets-tab">Tickets</button>
                  <button class="tab-btn" type="button" data-tab="ai-tab">IA</button>
                  <button class="tab-btn" type="button" data-tab="messages-tab">Mensajes</button>
                  <button class="tab-btn" type="button" data-tab="advanced-tab">Avanzado</button>
                </div>

                <div class="tab-panel active" id="tab-general"><h3>General</h3><div class="sub">Resumen rápido de la configuración del bot.</div>
                  <div class="grid">
                    <div class="card"><div class="feature-icon">◉</div><h3>Bot conectado</h3><p>${escapeHtml(guild.name,100)} está operativo y listo para recibir tickets.</p></div>
                    <div class="card"><div class="feature-icon">✦</div><h3>Modelo IA</h3><p>${escapeHtml(config.aiModel,80)} · idioma automático.</p></div>
                    <div class="card"><div class="feature-icon">📚</div><h3>Knowledge Base</h3><p>${String(cfg.knowledge || "").length.toLocaleString("es-ES")} caracteres configurados.</p></div>
                  </div>
                </div>

                <div class="tab-panel" id="tab-tickets-tab"><h3>Sistema de tickets</h3><div class="sub">Configura dónde se crean y quién recibe las escaladas.</div>
                  <div class="form-grid">
                    <div class="field"><label>Categoría de tickets</label><select name="ticketCategoryId"><option value="">Sin categoría específica</option>${categories}</select><div class="help">Los nuevos tickets se crearán dentro de esta categoría.</div></div>
                    <div class="field"><label>Rol del staff</label><select name="staffRoleId"><option value="">Detección automática</option>${roles}</select><div class="help">Este rol se prioriza para atención humana.</div></div>
                  </div>
                </div>

                <div class="tab-panel" id="tab-ai-tab"><h3>Inteligencia Artificial</h3><div class="sub">Enseña al agente cómo responder en tu servidor.</div>
                  <div class="notice">✦ <strong>Gemini ${escapeHtml(config.aiModel,80)}</strong> · El agente usa el historial persistente y la Knowledge Base como contexto prioritario.</div>
                  <label style="margin-top:16px">Knowledge Base</label>
                  <textarea name="knowledge" maxlength="100000">${escapeHtml(cfg.knowledge,100000)}</textarea>
                  <div class="help">Límite del plan ${escapeHtml(definition.name,40)}: ${formatLimit(definition.knowledgeChars,"caracteres")}.</div>
                </div>

                <div class="tab-panel" id="tab-messages-tab"><h3>Mensajes</h3><div class="sub">Texto que verá el usuario cuando abra un ticket.</div>
                  <label>Mensaje de bienvenida</label>
                  <textarea name="welcomeText" style="min-height:150px">${escapeHtml(cfg.welcomeText,1000)}</textarea>
                </div>

                <div class="tab-panel" id="tab-advanced-tab"><h3>Avanzado</h3><div class="sub">Configuración de escalado y responsable humano.</div>
                  <label>Founder ID / responsable de escaladas</label>
                  <input name="founderId" value="${escapeHtml(cfg.founderId,100)}" placeholder="ID de Discord">
                  <div class="help">Recibe los casos que requieren intervención humana.</div>
                </div>

                <div class="sticky-save"><button class="btn" type="submit">💾 Guardar cambios</button></div>
              </div>
            </form>
            <script>
              document.querySelectorAll(".tab-btn").forEach(function(btn){
                btn.addEventListener("click",function(){
                  document.querySelectorAll(".tab-btn").forEach(function(x){x.classList.remove("active")});
                  document.querySelectorAll(".tab-panel").forEach(function(x){x.classList.remove("active")});
                  btn.classList.add("active");
                  var panel=document.getElementById("tab-"+btn.dataset.tab);
                  if(panel) panel.classList.add("active");
                });
              });
            </script>
          </section>

          <section id="ai" class="section" style="margin-top:22px">
            <div class="section-head"><div><span class="pill">IA</span><h2>Estado del agente.</h2><p>Uso, contexto y escalado humano.</p></div></div>
            <div class="two-col"><div class="panel-card"><h3>Respuestas IA este mes</h3><div class="sub">${usage.aiResponses.toLocaleString("es-ES")} de ${definition.aiRepliesPerMonth.toLocaleString("es-ES")}</div><div class="progress" style="margin-top:14px"><span style="width:${aiPct}%"></span></div><div class="help">${aiPct}% utilizado</div></div><div class="panel-card"><h3>Escalado humano</h3><div class="sub">${stats.escalatedTickets} ticket(s) escalados</div><div class="kpi" style="margin-top:12px">${stats.escalatedTickets}</div></div></div>
          </section>

          <section id="knowledge" class="section" style="margin-top:22px"><div class="section-head"><div><span class="pill">Knowledge Base</span><h2>La memoria del servidor.</h2><p>El contenido se edita desde la pestaña IA.</p></div><span class="badge muted">${String(cfg.knowledge || "").length.toLocaleString("es-ES")} caracteres</span></div><div class="panel-card"><p class="muted">La IA utiliza estas reglas, FAQ y procedimientos como fuente prioritaria de contexto.</p></div></section>

          <section id="billing" class="section" style="margin-top:22px"><div class="section-head"><div><span class="pill">Facturación</span><h2>Tu plan actual.</h2><p>Gestiona Stripe y límites desde una pantalla.</p></div></div><div class="panel-card"><div class="toolbar"><div><h3>${escapeHtml(definition.name,40)} · ${escapeHtml(definition.price,20)}</h3><div class="sub">${escapeHtml(definition.billing,60)} · ${formatLimit(definition.ticketsPerMonth,"tickets/mes")} · ${formatLimit(definition.aiRepliesPerMonth,"respuestas IA/mes")}</div></div><a class="btn" href="/pricing?guild=${encodeURIComponent(guild.id)}">Gestionar plan</a></div><div class="grid" style="margin-top:15px"><div class="card"><div class="stat-label">Tickets</div><div class="kpi" style="font-size:28px">${usage.ticketsCreated}/${definition.ticketsPerMonth}</div><div class="progress" style="margin-top:9px"><span style="width:${ticketPct}%"></span></div></div><div class="card"><div class="stat-label">Respuestas IA</div><div class="kpi" style="font-size:28px">${usage.aiResponses}/${definition.aiRepliesPerMonth}</div><div class="progress" style="margin-top:9px"><span style="width:${aiPct}%"></span></div></div></div></div></section>

          <section id="activation" class="section" style="margin-top:22px"><div class="section-head"><div><span class="pill">Licencia</span><h2>Código de activación.</h2><p>Activa Pro o Lifetime sin pasar por Checkout.</p></div></div><div class="panel-card">${activationNotice}<form method="post" action="/api/servers/${encodeURIComponent(guild.id)}/activation-code"><div class="code-box"><input name="code" maxlength="32" autocomplete="off" placeholder="PRO-ABCD-EFGH o LIFE-ABCD-EFGH" required><button class="btn" type="submit">🔐 Activar</button></div></form><div class="help" style="margin-top:9px">Cada código es de un solo uso y queda asociado a este servidor.</div></div></section>
        </main>
      </div>
    `, session.user));
  } catch (error) {
    console.error("Dashboard server error:", error);
    res.status(500).send(htmlShell("Error", '<div class="card"><h2>⚠️ No se pudo cargar el servidor</h2><p class="error">' + escapeHtml(error.message,1000) + '</p><a class="btn alt" href="/dashboard">Volver</a></div>'));
  }
});


app.post("/api/servers/:guildId", rateLimit("server-config", 30, 5 * 60 * 1000), async (req, res) => {
  try {
    const session = await currentSession(req);
    if (!session) return res.status(401).send("Sesión requerida.");

    const access = await requireManagedGuild(req, session);
    if (!access) {
      return res.status(403).send("No autorizado.");
    }
    const { guild } = access;

    const body = req.body || {};
    const planState = await getGuildPlan(guild.id);
    const effectivePlanKey = planState.status === "active" ? normalizePlan(planState.plan) : "free";
    const planDefinition = getPlanDefinition(effectivePlanKey);
    const knowledge = cleanText(body.knowledge, 100000);

    if (knowledge.length > planDefinition.knowledgeChars) {
      return res.status(400).send(
        htmlShell("Límite de Knowledge Base",
          "<div class=\"card\"><h2>⚠️ Has superado el límite de tu plan</h2>" +
          "<p class=\"muted\">El plan " + escapeHtml(planDefinition.name,40) + " permite hasta " +
          formatLimit(planDefinition.knowledgeChars, "caracteres") + " en la Knowledge Base.</p>" +
          "<p class=\"muted\">Tu contenido actual tiene " + knowledge.length.toLocaleString("es-ES") + " caracteres.</p>" +
          "<a class=\"btn\" href=\"/pricing?guild=" + encodeURIComponent(guild.id) + "\">Ver planes</a></div>",
          session.user
        )
      );
    }

    await saveGuildConfig(guild.id, {
      founderId: cleanText(body.founderId,100).trim() || config.founderId,
      staffRoleId: cleanText(body.staffRoleId,100).trim(),
      ticketCategoryId: cleanText(body.ticketCategoryId,100).trim(),
      welcomeText: cleanText(body.welcomeText,1000).trim(),
      knowledge
    });

    await recordAuditLog({
      actorDiscordUserId: session.user.id,
      action: "guild_config_updated",
      guildId: guild.id,
      details: {
        knowledgeChars: knowledge.length,
        staffRoleConfigured: Boolean(cleanText(body.staffRoleId, 100).trim()),
        ticketCategoryConfigured: Boolean(cleanText(body.ticketCategoryId, 100).trim())
      }
    });

    res.redirect("/servers/" + encodeURIComponent(guild.id) + "?saved=1");
  } catch (error) {
    console.error("Config save error:", error);
    res.status(500).send("No se pudo guardar la configuración.");
  }
});

module.exports = {
  startDashboard({ client: discordClient }) {
    global.client = discordClient;
    app.listen(config.port, "0.0.0.0", () => {
      console.log(`🌐 Dashboard: ${config.dashboardUrl}`);
    });

    setInterval(() => {
      cleanupExpiredSessions().catch(error => {
        console.error("❌ Error limpiando sesiones expiradas:", error.message);
      });
    }, 15 * 60 * 1000).unref();
  }
};
