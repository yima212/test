const express = require("express");
const crypto = require("crypto");

const config = require("./config");
const { getGuildConfig, saveGuildConfig } = require("./db");

const app = express();
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

const sessions = new Map();
const oauthStates = new Map();


const DISCORD_API = "https://discord.com/api/v10";
const BOT_PERMISSIONS = "93200";

function cleanText(value, max = 5000) {
  return String(value ?? "").slice(0, max);
}

function issueSession(user, guilds) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    user,
    guilds,
    createdAt: Date.now()
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

function currentSession(req) {
  const token = parseCookies(req.headers.cookie).dashboard_session;
  return token ? sessions.get(token) : null;
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

function htmlShell(title, body, user = null) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · AI Support</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#09090b;color:#f4f4f5}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#18181b,#09090b 55%);min-height:100vh}
a{color:inherit;text-decoration:none}.wrap{max-width:1080px;margin:0 auto;padding:28px 20px}
.nav{display:flex;justify-content:space-between;align-items:center;padding:10px 0 28px}
.brand{font-weight:800;letter-spacing:.04em}.muted{color:#a1a1aa}.btn{display:inline-flex;align-items:center;gap:8px;border:0;border-radius:12px;padding:12px 16px;background:#5865f2;color:#fff;font-weight:700;cursor:pointer}
.btn.alt{background:#27272a}.card{background:rgba(24,24,27,.88);border:1px solid #27272a;border-radius:20px;padding:22px;margin-top:18px;box-shadow:0 16px 50px rgba(0,0,0,.18)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}.hero{padding:48px 0 24px}.hero h1{font-size:clamp(36px,7vw,70px);margin:0 0 14px;line-height:1}.hero p{font-size:18px;max-width:720px;color:#d4d4d8}
.kpi{font-size:30px;font-weight:800}.pill{display:inline-flex;padding:6px 10px;border-radius:999px;background:#18181b;border:1px solid #3f3f46;color:#d4d4d8;font-size:12px}
label{display:block;font-weight:700;margin:12px 0 6px}input,textarea,select{width:100%;border:1px solid #3f3f46;background:#111113;color:#fafafa;border-radius:12px;padding:12px 14px}textarea{min-height:150px;resize:vertical}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.guild{display:flex;justify-content:space-between;align-items:center;gap:14px}.guild strong{display:block}.small{font-size:13px}.error{color:#fca5a5}.success{color:#86efac}
@media(max-width:640px){.wrap{padding:18px 14px}.hero{padding-top:30px}}
</style>
</head>
<body><div class="wrap">
<div class="nav"><div class="brand">🤖 AI SUPPORT</div>${user ? '<div class="row"><span class="muted small">'+cleanText(user.username)+'</span><a class="btn alt" href="/logout">Salir</a></div>' : ''}</div>
${body}
</div></body></html>`;
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "discord-ai-support" }));

app.get("/auth/discord", (_req, res) => {
  if (!config.discordClientSecret) {
    return res.status(503).send(htmlShell("Configuración pendiente",
      '<div class="card"><h2>Falta Discord OAuth</h2><p class="muted">Añade DISCORD_CLIENT_SECRET en Railway y vuelve a intentarlo.</p></div>'
    ));
  }

  const state = crypto.randomBytes(20).toString("hex");
  oauthStates.set(state, Date.now());
  setTimeout(() => oauthStates.delete(state), 10 * 60 * 1000);

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.dashboardUrl + "/auth/discord/callback",
    response_type: "code",
    scope: "identify guilds",
    state
  });

  res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
});

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || !oauthStates.has(state)) {
      return res.status(400).send("Invalid OAuth state.");
    }
    oauthStates.delete(state);

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

    const headers = { Authorization: `Bearer ${tokenData.access_token}` };
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

    const sessionToken = issueSession(user, guilds);
    res.setHeader(
      "Set-Cookie",
      `dashboard_session=${encodeURIComponent(sessionToken)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
    );
    res.redirect("/dashboard");
  } catch (error) {
    console.error("OAuth error:", error);
    res.status(500).send(htmlShell("OAuth error",
      '<div class="card"><h2>⚠️ No se pudo iniciar sesión</h2><p class="error">'+cleanText(error.message,1000)+'</p></div>'
    ));
  }
});

app.get("/logout", (req, res) => {
  const token = parseCookies(req.headers.cookie).dashboard_session;
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", "dashboard_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  res.redirect("/");
});

app.get("/", (_req, res) => {
  const session = currentSession(_req);
  if (session) return res.redirect("/dashboard");

  res.send(htmlShell("AI Support", `
    <div class="hero">
      <span class="pill">Discord SaaS · MVP</span>
      <h1>Support que trabaja por ti.</h1>
      <p>Tickets privados, IA, escalado automático a staff y un dashboard para gestionar cada servidor.</p>
      <div class="row" style="margin-top:22px">
        <a class="btn" href="/auth/discord">Continuar con Discord</a>
        <a class="btn alt" href="/health">Estado</a>
      </div>
    </div>
    <div class="grid">
      <div class="card"><div class="kpi">🎫</div><h3>Tickets</h3><p class="muted">Crea soporte privado automáticamente.</p></div>
      <div class="card"><div class="kpi">🤖</div><h3>Agente IA</h3><p class="muted">Responde preguntas y mantiene contexto.</p></div>
      <div class="card"><div class="kpi">🛎️</div><h3>Escalado</h3><p class="muted">Contacta al staff cuando hace falta.</p></div>
    </div>
  `));

});

app.get("/dashboard", (req, res) => {
  const session = currentSession(req);
  if (!session) return res.redirect("/");

  const cards = session.guilds.map(guild => {
    const botIn = Boolean(client.guilds.cache.get(guild.id));
    return `
      <div class="card guild">
        <div>
          <strong>${cleanText(guild.name)}</strong>
          <span class="muted small">${botIn ? "🟢 Bot conectado" : "⚪ Bot no instalado"}</span>
        </div>
        <div class="row">
          ${botIn
            ? '<a class="btn" href="/servers/'+guild.id+'">Configurar</a>'
            : '<a class="btn" target="_blank" href="https://discord.com/oauth2/authorize?client_id='+encodeURIComponent(config.clientId)+'&scope=bot%20applications.commands&permissions='+BOT_PERMISSIONS+'&guild_id='+encodeURIComponent(guild.id)+'">Añadir bot</a>'}
        </div>
      </div>`;
  }).join("");

  res.send(htmlShell("Dashboard", `
    <div class="hero"><span class="pill">Panel de control</span><h1>Mis servidores</h1><p>Selecciona un servidor donde tengas permisos de gestión.</p></div>
    <div>${cards || '<div class="card"><p class="muted">No hay servidores disponibles.</p></div>'}</div>
  `, session.user));
});

app.get("/servers/:guildId", async (req, res) => {
  const session = currentSession(req);
  if (!session) return res.redirect("/");
  const guild = session.guilds.find(g => g.id === req.params.guildId);
  if (!guild) return res.status(403).send("No autorizado.");

  const botIn = Boolean(client.guilds.cache.get(guild.id));
  if (!botIn) return res.redirect("/dashboard");

  const cfg = await getGuildConfig(guild.id);

  res.send(htmlShell("Servidor", `
    <div class="hero"><span class="pill">${cleanText(guild.name)}</span><h1>Configuración</h1><p>Los cambios se aplican al servidor cuando guardes.</p></div>
    <div class="card">
      <form method="post" action="/api/servers/${guild.id}">
        <label>Founder ID</label>
        <input name="founderId" value="${cleanText(cfg.founderId,100)}" placeholder="ID de Discord">
        <label>Staff Role ID</label>
        <input name="staffRoleId" value="${cleanText(cfg.staffRoleId,100)}" placeholder="ID del rol de staff/moderación">
        <label>Mensaje de bienvenida</label>
        <textarea name="welcomeText">${cleanText(cfg.welcomeText,1000)}</textarea>
        <label>Base de conocimiento</label>
        <textarea name="knowledge" placeholder="FAQ, reglas, precios, procesos...
">${cleanText(cfg.knowledge,5000)}</textarea>
        <div class="row" style="margin-top:14px">
          <button class="btn" type="submit">Guardar configuración</button>
          <a class="btn alt" href="/dashboard">Volver</a>
        </div>
      </form>
    </div>
  `, session.user));
});

app.post("/api/servers/:guildId", async (req, res) => {
  const session = currentSession(req);
  if (!session) return res.status(401).send("Sesión requerida.");
  const guild = session.guilds.find(g => g.id === req.params.guildId);
  if (!guild || !client.guilds.cache.get(guild.id)) return res.status(403).send("No autorizado.");

  const body = req.body || {};
  await saveGuildConfig(guild.id, {
    founderId: cleanText(body.founderId,100).trim() || config.founderId,
    staffRoleId: cleanText(body.staffRoleId,100).trim(),
    welcomeText: cleanText(body.welcomeText,1000).trim(),
    knowledge: cleanText(body.knowledge,10000)
  });

  res.redirect("/servers/" + guild.id);
});

module.exports = {
  startDashboard({ client: discordClient }) {
    global.client = discordClient;
    app.listen(config.port, "0.0.0.0", () => {
      console.log(`🌐 Dashboard: ${config.dashboardUrl}`);
    });
  },
};
