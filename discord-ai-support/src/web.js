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
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title, 120)} · AI Support</title>
<style>
:root{
  color-scheme:dark;
  --bg:#07070a;--panel:#111116;--panel2:#16161c;--line:#27272f;
  --text:#f5f5f7;--muted:#a1a1aa;--brand:#5865f2;--success:#34d399;
  --warning:#f59e0b;--danger:#fb7185;--radius:18px;
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:
radial-gradient(circle at top right,rgba(88,101,242,.11),transparent 34%),
radial-gradient(circle at top left,rgba(56,189,248,.05),transparent 28%),
var(--bg);color:var(--text);min-height:100vh}
a{color:inherit;text-decoration:none}
button,input,textarea,select{font:inherit}
.wrap{max-width:1180px;margin:0 auto;padding:22px}
.nav{position:sticky;top:0;z-index:20;display:flex;justify-content:space-between;align-items:center;padding:10px 0 20px;background:linear-gradient(var(--bg) 70%,transparent)}
.brand{font-weight:900;letter-spacing:.04em;display:flex;gap:10px;align-items:center}
.brand-dot{width:12px;height:12px;border-radius:999px;background:var(--brand);box-shadow:0 0 25px rgba(88,101,242,.65)}
.userbar{display:flex;align-items:center;gap:12px}
.avatar{width:34px;height:34px;border-radius:12px;background:var(--panel2);display:grid;place-items:center;font-weight:800}
.small{font-size:13px}.muted{color:var(--muted)}
.hero{padding:42px 0 22px}
.hero h1{margin:8px 0 12px;font-size:clamp(38px,6vw,68px);line-height:.98;letter-spacing:-.045em}
.hero p{max-width:760px;font-size:18px;line-height:1.6;color:#d4d4d8}
.pill{display:inline-flex;align-items:center;padding:7px 11px;border-radius:999px;background:#121218;border:1px solid #30303a;color:#d4d4d8;font-size:12px;font-weight:700}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid transparent;border-radius:12px;padding:12px 16px;background:var(--brand);color:#fff;font-weight:800;cursor:pointer;transition:.18s transform,.18s opacity}
.btn:hover{transform:translateY(-1px);opacity:.94}
.btn.alt{background:#1b1b22;border-color:#2b2b35}
.btn.ghost{background:transparent;border-color:#2d2d38}
.btn.danger{background:#2a1217;border-color:#4a1f28}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}
.card{background:linear-gradient(180deg,rgba(24,24,30,.96),rgba(16,16,21,.96));border:1px solid var(--line);border-radius:var(--radius);padding:20px;box-shadow:0 18px 55px rgba(0,0,0,.2)}
.card h2,.card h3{margin:0 0 8px}
.kpi{font-size:34px;font-weight:900;letter-spacing:-.04em}
.stat-label{color:var(--muted);font-size:13px}
.server{display:flex;align-items:center;gap:14px}
.server-icon{width:50px;height:50px;border-radius:16px;display:grid;place-items:center;background:#1c1c24;border:1px solid #30303a;overflow:hidden;flex:0 0 auto}
.server-icon img{width:100%;height:100%;object-fit:cover}
.server-meta{min-width:0;flex:1}
.server-name{font-weight:850;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.status{display:inline-flex;align-items:center;gap:6px;margin-top:4px;font-size:12px;color:var(--muted)}
.status-dot{width:7px;height:7px;border-radius:50%}.online{background:var(--success)}.offline{background:#71717a}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.side-layout{display:grid;grid-template-columns:220px minmax(0,1fr);gap:20px;align-items:start}
.sidebar{position:sticky;top:72px;padding:10px}
.sidebar a{display:block;padding:10px 12px;border-radius:11px;color:#c4c4cc;font-size:14px;margin-bottom:4px}
.sidebar a:hover{background:#15151c;color:#fff}
.section{scroll-margin-top:90px}
.section-title{display:flex;align-items:end;justify-content:space-between;gap:12px;margin-bottom:12px}
.section-title h2{font-size:22px}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.field.full{grid-column:1/-1}
label{display:block;font-weight:800;font-size:13px;margin:0 0 7px}
input,textarea,select{width:100%;border:1px solid #3a3a45;background:#0d0d12;color:#fafafa;border-radius:12px;padding:12px 13px;outline:none}
input:focus,textarea:focus,select:focus{border-color:#646cff;box-shadow:0 0 0 3px rgba(88,101,242,.15)}
textarea{min-height:170px;resize:vertical}
.help{margin-top:6px;color:var(--muted);font-size:12px;line-height:1.45}
.toolbar{display:flex;gap:10px;justify-content:space-between;align-items:center;flex-wrap:wrap}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px}
table{width:100%;border-collapse:collapse;min-width:640px}
th,td{padding:12px 14px;border-bottom:1px solid #23232b;text-align:left;font-size:13px}
th{color:#a7a7b2;font-weight:800;background:#121219}
tr:last-child td{border-bottom:0}
.badge{display:inline-flex;padding:5px 9px;border-radius:999px;font-size:11px;font-weight:800;border:1px solid #32323c}
.badge.success{color:#86efac;background:#0d211a;border-color:#164b35}
.badge.warning{color:#fcd34d;background:#231d0c;border-color:#574611}
.badge.muted{background:#18181f}
.notice{padding:13px 15px;border-radius:13px;background:#111826;border:1px solid #1d355d;color:#c7d2fe;font-size:13px;line-height:1.5}
.footer{padding:45px 0 15px;text-align:center;color:#71717a;font-size:12px}
.divider{height:1px;background:#25252d;margin:4px 0 0}
@media(max-width:820px){.side-layout{grid-template-columns:1fr}.sidebar{position:static;display:flex;overflow:auto;gap:6px;padding:0}.sidebar a{white-space:nowrap}.form-grid{grid-template-columns:1fr}.field.full{grid-column:auto}}
@media(max-width:640px){.wrap{padding:16px}.nav{padding-bottom:12px}.hero{padding-top:28px}.hero h1{font-size:42px}.userbar .small{display:none}.card{padding:17px}}
</style>
</head>
<body>
<div class="wrap">
<div class="nav">
  <a class="brand" href="/dashboard"><span class="brand-dot"></span>AI SUPPORT</a>
  ${user ? '<div class="userbar"><div class="avatar">'+escapeHtml((user.username || "?").slice(0,1).toUpperCase(),1)+'</div><span class="muted small">'+escapeHtml(user.username,80)+'</span>' +
    (isFounder({ user }) ? '<a class="btn alt" href="/admin">Admin</a>' : '') +
    '<a class="btn alt" href="/logout">Salir</a></div>' : ''}
</div>
${body}
<div class="footer">AI Support · Discord SaaS</div>
</div>
</body></html>`;
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

  res.send(htmlShell("AI Support", `
    <div class="hero">
      <span class="pill">Discord SaaS · AI Support</span>
      <h1>El soporte de tu comunidad, en automático.</h1>
      <p>Tickets privados, asistente IA multilingüe, escalado a staff, base de conocimiento y persistencia por servidor.</p>
      <div class="actions" style="margin-top:20px">
        <a class="btn" href="/auth/discord">Continuar con Discord</a>
        <a class="btn alt" href="/health">Estado</a>
      </div>
    </div>
    <div class="grid">
      <div class="card"><div class="kpi">🎫</div><h3>Tickets</h3><p class="muted">Conversaciones privadas y persistentes.</p></div>
      <div class="card"><div class="kpi">🤖</div><h3>IA</h3><p class="muted">Respuestas según la base de conocimiento de cada servidor.</p></div>
      <div class="card"><div class="kpi">🛎️</div><h3>Escalado</h3><p class="muted">Entrega los casos complejos al equipo humano.</p></div>
    </div>
  `));
});


app.get("/pricing", async (req, res) => {
  const session = await currentSession(req);
  if (!session) return res.redirect("/");

  const guildId = cleanText(req.query.guild, 100).trim();
  if (!guildId) {
    const serverLinks = session.guilds.map(guild =>
      "<div class=\"card\"><div class=\"server\">" +
      "<div class=\"server-icon\">" +
        (discordIconUrl(guild) ? "<img src=\"" + escapeHtml(discordIconUrl(guild),300) + "\" alt=\"\">" : "◎") +
      "</div>" +
      "<div class=\"server-meta\"><div class=\"server-name\">" + escapeHtml(guild.name,100) + "</div>" +
      "<div class=\"status\">Gestionar facturación de este servidor</div></div>" +
      "<a class=\"btn\" href=\"/pricing?guild=" + encodeURIComponent(guild.id) + "\">Ver planes</a>" +
      "</div></div>"
    ).join("");

    return res.send(htmlShell("Planes",
      "<div class=\"hero\">" +
      "<span class=\"pill\">SaaS · Stripe</span>" +
      "<h1>Selecciona un servidor.</h1>" +
      "<p>Los planes se contratan por servidor de Discord, no por cuenta global.</p>" +
      "</div><div>" +
      (serverLinks || "<div class=\"card\"><p class=\"muted\">No hay servidores gestionables.</p></div>") +
      "</div>",
      session.user
    ));
  }

  const guild = session.guilds.find(g => g.id === guildId);
  if (!guild) return res.status(403).send("No autorizado.");

  const planState = await getGuildPlan(guild.id);
  const currentPlanKey = planState.status === "active" ? normalizePlan(planState.plan) : "free";
  const currentPlan = getPlanDefinition(currentPlanKey);
  const currentPlanBlock = currentPlanKey === "free"
    ? "<span class=\"badge muted\">FREE</span>"
    : "<span class=\"badge success\">" + escapeHtml(currentPlan.name,30) + " · " + escapeHtml(planState.status,30) + "</span>";

  const portalButton = planState.stripeCustomerId
    ? "<a class=\"btn alt\" href=\"/billing/portal/" + encodeURIComponent(guild.id) + "\">Gestionar facturación</a>"
    : "";

  const canBuyPaid = currentPlanKey === "free";
  const proButton = canBuyPaid
    ? "<form method=\"post\" action=\"/billing/checkout/" + encodeURIComponent(guild.id) + "/pro\" style=\"margin:0\"><button class=\"btn\" type=\"submit\">Contratar Pro · $6/mes</button></form>"
    : "<span class=\"badge muted\">Plan ya activo</span>";

  const lifetimeButton = canBuyPaid
    ? "<form method=\"post\" action=\"/billing/checkout/" + encodeURIComponent(guild.id) + "/lifetime\" style=\"margin:0\"><button class=\"btn\" type=\"submit\">Comprar Lifetime · $30</button></form>"
    : "<span class=\"badge muted\">Plan ya activo</span>";

  const planCards = Object.values(PLAN_DEFINITIONS).map(def => {
    const priceSuffix = def.key === "pro"
      ? "<span style=\"font-size:15px;color:#a1a1aa\">/mes</span>"
      : "";
    const features = def.features.map(feature => "<div class=\"help\">✓ " + escapeHtml(feature,160) + "</div>").join("");
    const limits =
      "<div class=\"help\"><strong>" + formatLimit(def.ticketsPerMonth, "tickets nuevos/mes") + "</strong></div>" +
      "<div class=\"help\"><strong>" + formatLimit(def.aiRepliesPerMonth, "respuestas IA/mes") + "</strong></div>" +
      "<div class=\"help\"><strong>" + formatLimit(def.knowledgeChars, "caracteres de Knowledge Base") + "</strong></div>";
    const action = def.key === "free"
      ? "<span class=\"badge muted\">Incluido</span>"
      : def.key === "pro"
        ? proButton
        : lifetimeButton;

    return "<div class=\"card\">" +
      "<span class=\"pill\">" + escapeHtml(def.name.toUpperCase(),30) + "</span>" +
      "<h2 style=\"margin-top:12px\">" + escapeHtml(def.name,40) + "</h2>" +
      "<div class=\"kpi\">" + escapeHtml(def.price,20) + priceSuffix + "</div>" +
      "<p class=\"muted\">" + escapeHtml(def.billing,80) + ".</p>" +
      "<div style=\"margin-top:12px\">" + limits + features + "</div>" +
      "<div class=\"actions\" style=\"margin-top:16px\">" + action + "</div>" +
      "</div>";
  }).join("");

  return res.send(htmlShell("Planes",
    "<div class=\"hero\">" +
      "<span class=\"pill\">SaaS · " + escapeHtml(guild.name,100) + "</span>" +
      "<h1>Planes AI Support.</h1>" +
      "<p>Cada servidor tiene su propio plan y su propio límite mensual de uso. Los límites se reinician al comenzar cada mes en horario de España.</p>" +
    "</div>" +
    "<div class=\"card\" style=\"margin-bottom:18px\"><div class=\"toolbar\">" +
      "<div><strong>Servidor</strong><div class=\"muted small\">" + escapeHtml(guild.name,100) + "</div></div>" +
      "<div class=\"actions\">" + currentPlanBlock + portalButton + "</div>" +
    "</div></div>" +
    "<div class=\"grid\">" + planCards + "</div>" +
    "<div class=\"card\" style=\"margin-top:18px\"><div class=\"notice\"><strong>Uso justo:</strong> Lifetime no tiene renovación mensual, pero mantiene límites mensuales de uso para evitar abuso y mantener el servicio sostenible.</div></div>" +
    "<div class=\"card\" style=\"margin-top:18px\"><div class=\"toolbar\">" +
      "<div><strong>Facturación segura</strong><div class=\"muted small\">" +
        (stripe ? "Stripe está preparado para Checkout." : "Añade STRIPE_SECRET_KEY en Railway para activar los cobros.") +
      "</div></div>" +
      "<a class=\"btn alt\" href=\"/servers/" + encodeURIComponent(guild.id) + "\">← Volver al servidor</a>" +
    "</div></div>",
    session.user
  ));
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
    if (!isFounder(session)) return res.status(403).send(htmlShell("No autorizado",
      '<div class="card"><h2>403 · No autorizado</h2><p class="muted">Este panel está reservado al administrador principal del SaaS.</p><a class="btn alt" href="/dashboard">Volver</a></div>',
      session.user
    ));

    const [stats, codes] = await Promise.all([
      getActivationCodeStats(),
      listActivationCodes(100)
    ]);

    const generatedNotice = req.query.generated === "1"
      ? '<div class="notice"><strong>✅ Lote generado.</strong> Los códigos se muestran solo en la pantalla de generación.</div>'
      : "";
    const disabledNotice = req.query.disabled === "1"
      ? '<div class="notice"><strong>✅ Código desactivado.</strong></div>'
      : req.query.disabled === "0"
        ? '<div class="notice" style="border-color:#5b2532;background:#1a0f14;color:#fecdd3"><strong>⚠️ No se encontró un código disponible con ese valor.</strong></div>'
        : "";

    const rows = codes.map(code => {
      const effectiveStatus = String(code.status || "").toLowerCase();
      const statusClass =
        effectiveStatus === "available" ? "success" :
        effectiveStatus === "used" ? "muted" :
        "warning";
      const statusLabel =
        effectiveStatus === "available" ? "Disponible" :
        effectiveStatus === "used" ? "Usado" :
        effectiveStatus === "expired" ? "Caducado" :
        "Desactivado";
      return `<tr>
        <td><strong>${escapeHtml(code.code_hint,40)}••••</strong></td>
        <td>${escapeHtml(getPlanDefinition(normalizePlan(code.plan)).name,40)}</td>
        <td><span class="badge ${statusClass}">${escapeHtml(statusLabel,30)}</span></td>
        <td>${escapeHtml(formatDate(code.created_at),80)}</td>
        <td>${escapeHtml(formatDate(code.expires_at),80)}</td>
        <td>${code.redeemed_guild_id ? escapeHtml(code.redeemed_guild_id,80) : "—"}</td>
      </tr>`;
    }).join("");

    res.send(htmlShell("Admin · Códigos", `
      <div class="hero">
        <span class="pill">🔐 Administración segura</span>
        <h1>Licencias y códigos.</h1>
        <p>Generación server-side de códigos de un solo uso. Solo tu cuenta de Discord, configurada como FOUNDER_USER_ID, puede acceder a este panel.</p>
      </div>

      ${generatedNotice}
      ${disabledNotice}

      <div class="grid">
        <div class="card"><div class="kpi">${stats.total}</div><div class="stat-label">Códigos totales</div></div>
        <div class="card"><div class="kpi">${stats.available}</div><div class="stat-label">Disponibles</div></div>
        <div class="card"><div class="kpi">${stats.used}</div><div class="stat-label">Usados</div></div>
        <div class="card"><div class="kpi">${stats.disabledOrExpired}</div><div class="stat-label">Desactivados/caducados</div></div>
      </div>

      <section class="section" style="margin-top:28px">
        <div class="section-title"><h2>Generar lote</h2><span class="muted small">Máximo 100 por solicitud</span></div>
        <div class="card">
          <form method="post" action="/admin/activation-codes/generate">
            <div class="form-grid">
              <div class="field">
                <label>Plan</label>
                <select name="plan">
                  <option value="pro">Pro · $6/mes</option>
                  <option value="lifetime">Lifetime · $30</option>
                </select>
              </div>
              <div class="field">
                <label>Cantidad</label>
                <select name="quantity">
                  <option>1</option>
                  <option>10</option>
                  <option>50</option>
                  <option>100</option>
                </select>
              </div>
              <div class="field full">
                <label>Caducidad opcional</label>
                <input type="datetime-local" name="expiresAt">
                <div class="help">La fecha se valida en el servidor. La caducidad del código no revoca un plan que ya haya sido activado.</div>
              </div>
            </div>
            <div class="toolbar" style="margin-top:16px">
              <a class="btn alt" href="/dashboard">← Volver</a>
              <button class="btn" type="submit">🪙 Generar códigos</button>
            </div>
          </form>
        </div>
      </section>

      <section class="section" style="margin-top:28px">
        <div class="section-title"><h2>Invalidar código</h2><span class="muted small">Solo códigos disponibles</span></div>
        <div class="card">
          <form method="post" action="/admin/activation-codes/disable">
            <div class="toolbar" style="align-items:stretch">
              <input name="code" maxlength="32" autocomplete="off" placeholder="Pega aquí el código completo" required style="flex:1;min-width:240px">
              <button class="btn danger" type="submit">Desactivar</button>
            </div>
          </form>
          <div class="help" style="margin-top:10px">Los códigos completos no se almacenan en texto plano; después de salir de la pantalla de generación solo se conserva su hash y una referencia parcial.</div>
        </div>
      </section>

      <section class="section" style="margin-top:28px">
        <div class="section-title"><h2>Actividad</h2><span class="muted small">Últimos 100</span></div>
        <div class="card">
          ${rows
            ? '<div class="table-wrap"><table><thead><tr><th>Código</th><th>Plan</th><th>Estado</th><th>Creado</th><th>Expira</th><th>Servidor usado</th></tr></thead><tbody>'+rows+'</tbody></table></div>'
            : '<p class="muted">Todavía no has generado códigos.</p>'}
        </div>
      </section>
    `, session.user));
  } catch (error) {
    console.error("Admin dashboard error:", error);
    res.status(500).send(htmlShell("Error",
      '<div class="card"><h2>⚠️ No se pudo cargar la administración</h2><p class="error">'+escapeHtml(error.message,1000)+'</p><a class="btn alt" href="/dashboard">Volver</a></div>'
    ));
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

    if (!["pro", "lifetime"].includes(plan)) {
      return res.status(400).send("Plan no válido.");
    }

    const codes = await createActivationCodes({
      plan,
      quantity,
      expiresAt,
      createdByDiscordUserId: session.user.id
    });

    await recordAuditLog({
      actorDiscordUserId: session.user.id,
      action: "activation_codes_generated",
      details: {
        plan,
        quantity: codes.length,
        expiresAt
      }
    });

    const codeText = codes.join("\n");
    const downloadHref = "data:text/plain;charset=utf-8," + encodeURIComponent(codeText);

    res.setHeader("Cache-Control", "no-store, private");
    res.send(htmlShell("Códigos generados", `
      <div class="hero">
        <span class="pill">✅ Lote creado</span>
        <h1>${codes.length} códigos ${escapeHtml(getPlanDefinition(plan).name,40)}.</h1>
        <p>Guárdalos ahora. Por seguridad, la aplicación no vuelve a mostrar los códigos completos después de esta pantalla.</p>
      </div>
      <div class="card">
        <textarea id="generated-codes" readonly style="min-height:340px">${escapeHtml(codeText,10000)}</textarea>
        <div class="actions" style="margin-top:14px">
          <button class="btn" type="button" onclick="navigator.clipboard.writeText(document.getElementById('generated-codes').value)">📋 Copiar todos</button>
          <a class="btn alt" href="${escapeHtml(downloadHref,20000)}" download="activation-codes-${escapeHtml(plan,20)}.txt">⬇️ Descargar TXT</a>
          <a class="btn alt" href="/admin?generated=1">← Administración</a>
        </div>
      </div>
    `, session.user));
  } catch (error) {
    console.error("Activation code generation error:", error);
    res.status(400).send(htmlShell("Error",
      '<div class="card"><h2>⚠️ No se pudieron generar los códigos</h2><p class="error">'+escapeHtml(error.message,1000)+'</p><a class="btn alt" href="/admin">Volver</a></div>',
      (await currentSession(req))?.user || null
    ));
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

  const cards = session.guilds.map(guild => {
    const botIn = Boolean(client.guilds.cache.get(guild.id));
    const icon = discordIconUrl(guild);
    return `
      <div class="card">
        <div class="server">
          <div class="server-icon">${icon ? '<img src="'+escapeHtml(icon,300)+'" alt="">' : '◎'}</div>
          <div class="server-meta">
            <div class="server-name">${escapeHtml(guild.name,100)}</div>
            <div class="status"><span class="status-dot ${botIn ? "online" : "offline"}"></span>${botIn ? "Bot conectado" : "Bot no instalado"}</div>
          </div>
          <div class="actions">
            ${botIn
              ? '<a class="btn" href="/servers/'+encodeURIComponent(guild.id)+'">Abrir panel</a>'
              : '<a class="btn" href="/servers/'+encodeURIComponent(guild.id)+'/install">Añadir bot</a>'}
          </div>
        </div>
      </div>`;
  }).join("");

  res.send(htmlShell("Dashboard", `
    <div class="hero">
      <span class="pill">Panel de control</span>
      <h1>Mis servidores</h1>
      <p>Gestiona tickets, IA, staff y la base de conocimiento de cada servidor desde un solo lugar.</p>
    </div>
    <div class="grid">
      <div class="card"><div class="kpi">${session.guilds.length}</div><div class="stat-label">Servidores gestionables</div></div>
      <div class="card"><div class="kpi">${session.guilds.filter(g => client.guilds.cache.has(g.id)).length}</div><div class="stat-label">Servidores con bot</div></div>
      <div class="card"><div class="kpi">∞</div><div class="stat-label">Configuración por servidor</div></div>
    </div>
    <div style="margin-top:18px">${cards || '<div class="card"><p class="muted">No hay servidores disponibles.</p></div>'}</div>
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

    const effectivePlanKey = plan.status === "active" ? normalizePlan(plan.plan) : "free";
    const planDefinition = getPlanDefinition(effectivePlanKey);

    const categories = discordGuild.channels.cache
      .filter(ch => ch.type === 4)
      .sort((a,b) => a.position - b.position)
      .map(ch => '<option value="'+escapeHtml(ch.id,80)+'" '+(cfg.ticketCategoryId === ch.id ? "selected" : "")+'>'+escapeHtml(ch.name,100)+'</option>')
      .join("");

    const roles = Array.from(
      discordGuild.roles.cache
        .filter(role => role.id !== discordGuild.id && !role.managed)
        .values()
    )
      .sort((a,b) => b.position - a.position)
      .slice(0, 100)
      .map(role => '<option value="'+escapeHtml(role.id,80)+'" '+(cfg.staffRoleId === role.id ? "selected" : "")+'>'+escapeHtml(role.name,100)+'</option>')
      .join("");

    const rows = recentTickets.map(ticket => {
      const channel = discordGuild.channels.cache.get(ticket.channel_id);
      const status = ticket.status === "open"
        ? '<span class="badge success">Abierto</span>'
        : '<span class="badge muted">Cerrado</span>';
      const escalated = ticket.escalated
        ? '<span class="badge warning">Escalado</span>'
        : '<span class="badge muted">Normal</span>';
      const link = channel
        ? '<a class="btn ghost small" href="'+escapeHtml(channel.url,400)+'" target="_blank" rel="noopener">Discord</a>'
        : '<span class="muted">No disponible</span>';
      return `<tr>
        <td><strong>${escapeHtml(channel?.name || ticket.channel_id,100)}</strong></td>
        <td>${escapeHtml(ticket.owner_id,80)}</td>
        <td>${status}</td>
        <td>${escalated}</td>
        <td>${escapeHtml(formatDate(ticket.created_at),80)}</td>
        <td>${link}</td>
      </tr>`;
    }).join("");

    const icon = discordIconUrl(guild);

    const activationState = cleanText(req.query.activation, 30).trim().toLowerCase();
    const activationPlan = normalizePlan(cleanText(req.query.plan, 30).trim());
    const activationNotice = activationState === "success"
      ? '<div class="notice"><strong>✅ Código activado.</strong> El servidor ahora tiene el plan ' + escapeHtml(getPlanDefinition(activationPlan).name, 40) + '.</div>'
      : activationState
        ? '<div class="notice" style="border-color:#5b2532;background:#1a0f14;color:#fecdd3"><strong>⚠️ No se activó el código.</strong> ' + escapeHtml(activationReasonMessage(activationState), 300) + '</div>'
        : '';


    res.send(htmlShell("Panel · " + guild.name, `
      <div class="hero">
        <span class="pill">${icon ? '<img src="'+escapeHtml(icon,300)+'" style="width:20px;height:20px;border-radius:7px;margin-right:7px;vertical-align:-5px" alt="">' : ''}${escapeHtml(guild.name,100)}</span>
        <h1>Panel del servidor</h1>
        <p>Configura el comportamiento del soporte y consulta el estado de tus tickets.</p>
      </div>

      <div class="side-layout">
        <aside class="sidebar card">
          <a href="#overview">📊 Resumen</a>
          <a href="#tickets">🎫 Tickets</a>
          <a href="#ai">🤖 IA</a>
          <a href="#staff">👥 Staff</a>
          <a href="#knowledge">📚 Knowledge Base</a>
          <a href="#billing">💳 Plan</a>
          <a href="#activation">🔑 Código</a>
        </aside>

        <main>
          <section id="overview" class="section">
            <div class="section-title">
                <h2>Resumen</h2>
                <div class="actions">
                  <span class="pill">🟢 Bot conectado</span>
                  <a class="btn alt small" href="/pricing?guild=${encodeURIComponent(guild.id)}">Ver planes</a>
                </div>
              </div>
            <div class="grid">
              <div class="card"><div class="kpi">${stats.totalTickets}</div><div class="stat-label">Tickets totales</div></div>
              <div class="card"><div class="kpi">${stats.openTickets}</div><div class="stat-label">Tickets abiertos</div></div>
              <div class="card"><div class="kpi">${stats.closedTickets}</div><div class="stat-label">Tickets cerrados</div></div>
              <div class="card"><div class="kpi">${stats.escalatedTickets}</div><div class="stat-label">Escalados a humano</div></div>
              <div class="card"><div class="kpi">${escapeHtml(String(usage.aiResponses),20)} / ${escapeHtml(String(planDefinition.aiRepliesPerMonth),20)}</div><div class="stat-label">Respuestas IA este mes</div></div>
              <div class="card"><div class="kpi">${escapeHtml(String(usage.ticketsCreated),20)} / ${escapeHtml(String(planDefinition.ticketsPerMonth),20)}</div><div class="stat-label">Tickets nuevos este mes</div></div>
              <div class="card"><div class="kpi">${escapeHtml(String(plan.plan).toUpperCase(),20)}</div><div class="stat-label">Plan actual · ${escapeHtml(plan.status,30)}</div></div>
            </div>
          </section>

          <section id="tickets" class="section" style="margin-top:28px">
            <div class="section-title"><h2>Tickets</h2><span class="muted small">Últimos 10</span></div>
            <div class="card">
              ${rows
                ? '<div class="table-wrap"><table><thead><tr><th>Canal</th><th>Usuario</th><th>Estado</th><th>Escalado</th><th>Creado</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>'
                : '<p class="muted">Todavía no hay tickets registrados.</p>'}
            </div>
          </section>

          <form method="post" action="/api/servers/${encodeURIComponent(guild.id)}">
            <section id="ai" class="section" style="margin-top:28px">
              <div class="section-title"><h2>IA</h2><span class="pill">Gemini · ${escapeHtml(config.aiModel,80)}</span></div>
              <div class="card">
                <div class="notice">
                  🌍 El agente detecta automáticamente el idioma del cliente y mantiene el idioma durante la conversación.
                  La IA utiliza la Knowledge Base de este servidor como fuente prioritaria.
                </div>
                <div class="grid" style="margin-top:16px">
                  <div class="card" style="margin-top:0"><div class="kpi">🌐</div><h3>Multilingüe</h3><p class="muted">Detecta y mantiene el idioma del cliente.</p></div>
                  <div class="card" style="margin-top:0"><div class="kpi">🧠</div><h3>Contexto</h3><p class="muted">Usa el historial persistente del ticket.</p></div>
                  <div class="card" style="margin-top:0"><div class="kpi">📚</div><h3>Knowledge Base</h3><p class="muted">${String(cfg.knowledge || "").length} caracteres configurados.</p></div>
                </div>
              </div>
            </section>

            <section id="staff" class="section" style="margin-top:28px">
              <div class="section-title"><h2>Staff y tickets</h2><span class="muted small">Configuración por servidor</span></div>
              <div class="card">
                <div class="form-grid">
                  <div class="field">
                    <label>Founder ID</label>
                    <input name="founderId" value="${escapeHtml(cfg.founderId,100)}" placeholder="ID de Discord">
                    <div class="help">Persona que recibe las escaladas y casos que requieren atención humana.</div>
                  </div>
                  <div class="field">
                    <label>Staff Role</label>
                    <select name="staffRoleId">
                      <option value="">Usar detección automática</option>
                      ${roles}
                    </select>
                  </div>
                  <div class="field">
                    <label>Categoría de tickets</label>
                    <select name="ticketCategoryId">
                      <option value="">Sin categoría específica</option>
                      ${categories}
                    </select>
                  </div>
                  <div class="field">
                    <label>Estado</label>
                    <input value="🟢 Bot conectado en este servidor" disabled>
                  </div>
                </div>
              </div>
            </section>

            <section id="billing" class="section" style="margin-top:28px">
              <div class="section-title"><h2>Plan y facturación</h2><span class="muted small">Estado actual del servidor</span></div>
              <div class="card">
                <div class="toolbar">
                  <div>
                    <span class="pill">${escapeHtml(String(plan.plan).toUpperCase(),20)}</span>
                    <h3 style="margin-top:10px">Plan ${escapeHtml(String(plan.plan),20)}</h3>
                    <p class="muted">Estado: ${escapeHtml(plan.status,30)} · Los planes y cobros se aplicarán por servidor.</p>
                  </div>
                  <a class="btn" href="/pricing?guild=${encodeURIComponent(guild.id)}">Gestionar plan</a>
                </div>
              </div>
            </section>

            <section id="knowledge" class="section" style="margin-top:28px">
              <div class="section-title"><h2>Knowledge Base</h2><span class="muted small">Reglas y documentación del servidor</span></div>
              <div class="card">
                <label>Mensaje de bienvenida</label>
                <textarea name="welcomeText" style="min-height:110px">${escapeHtml(cfg.welcomeText,1000)}</textarea>
                <div class="help">Aparece automáticamente cuando se abre un ticket.</div>

                <label style="margin-top:18px">Base de conocimiento</label>
                <textarea name="knowledge">${escapeHtml(cfg.knowledge,100000)}</textarea>
                <div class="help">Límite del plan ${planDefinition.name}: ${formatLimit(planDefinition.knowledgeChars, "caracteres")}. Introduce reglas, FAQ, precios, procedimientos y documentación que la IA puede utilizar.</div>

                <div class="toolbar" style="margin-top:16px">
                  <a class="btn alt" href="/dashboard">← Volver</a>
                  <button class="btn" type="submit">💾 Guardar cambios</button>
                </div>
              </div>
            </section>
          </form>

          <section id="activation" class="section" style="margin-top:28px">
            <div class="section-title">
              <h2>Código de activación</h2>
              <span class="muted small">Licencias entregadas por administración</span>
            </div>
            <div class="card">
              ${activationNotice}
              <p class="muted">Introduce un código Pro o Lifetime que te haya entregado el administrador. Cada código es de un solo uso y queda asociado a este servidor.</p>
              <form method="post" action="/api/servers/${encodeURIComponent(guild.id)}/activation-code">
                <div class="toolbar" style="align-items:stretch">
                  <input name="code" maxlength="32" autocomplete="off" placeholder="PRO-ABCD-EFGH o LIFE-ABCD-EFGH" required style="flex:1;min-width:240px">
                  <button class="btn" type="submit">🔐 Activar código</button>
                </div>
              </form>
              <div class="help" style="margin-top:10px">La activación por código es independiente de Stripe. Un servidor con un plan activo no puede volver a activar otro código.</div>
            </div>
          </section>
        </main>
      </div>
    `, session.user));
  } catch (error) {
    console.error("Dashboard server error:", error);
    res.status(500).send(htmlShell("Error",
      '<div class="card"><h2>⚠️ No se pudo cargar el servidor</h2><p class="error">'+escapeHtml(error.message,1000)+'</p><a class="btn alt" href="/dashboard">Volver</a></div>'
    ));
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
