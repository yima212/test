const express = require("express");
const crypto = require("crypto");

const config = require("./config");
const {
  getGuildConfig,
  saveGuildConfig,
  getGuildDashboardStats,
  getRecentGuildTickets
} = require("./db");

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

function discordIconUrl(guild) {
  if (!guild?.icon) return "";
  return `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png?size=128`;
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
  ${user ? '<div class="userbar"><div class="avatar">'+escapeHtml((user.username || "?").slice(0,1).toUpperCase(),1)+'</div><span class="muted small">'+escapeHtml(user.username,80)+'</span><a class="btn alt" href="/logout">Salir</a></div>' : ''}
</div>
${body}
<div class="footer">AI Support · Discord SaaS</div>
</div>
</body></html>`;
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "discord-ai-support" });
});

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

    const sessionToken = issueSession(user, guilds);
    res.setHeader(
      "Set-Cookie",
      "dashboard_session=" + encodeURIComponent(sessionToken) + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400"
    );
    res.redirect("/dashboard");
  } catch (error) {
    console.error("OAuth error:", error);
    res.status(500).send(htmlShell("OAuth error",
      '<div class="card"><h2>⚠️ No se pudo iniciar sesión</h2><p class="error">'+escapeHtml(error.message,1000)+'</p></div>'
    ));
  }
});

app.get("/logout", (req, res) => {
  const token = parseCookies(req.headers.cookie).dashboard_session;
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", "dashboard_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  res.redirect("/");
});

app.get("/", (req, res) => {
  const session = currentSession(req);
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

app.get("/dashboard", (req, res) => {
  const session = currentSession(req);
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
              : '<a class="btn" target="_blank" rel="noopener" href="https://discord.com/oauth2/authorize?client_id='+encodeURIComponent(config.clientId)+'&scope=bot%20applications.commands&permissions='+BOT_PERMISSIONS+'&guild_id='+encodeURIComponent(guild.id)+'">Añadir bot</a>'}
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
    const session = currentSession(req);
    if (!session) return res.redirect("/");

    const guild = session.guilds.find(g => g.id === req.params.guildId);
    if (!guild) return res.status(403).send("No autorizado.");

    const discordGuild = client.guilds.cache.get(guild.id);
    if (!discordGuild) return res.redirect("/dashboard");

    const [cfg, stats, recentTickets] = await Promise.all([
      getGuildConfig(guild.id),
      getGuildDashboardStats(guild.id),
      getRecentGuildTickets(guild.id, 10)
    ]);

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
        </aside>

        <main>
          <section id="overview" class="section">
            <div class="section-title"><h2>Resumen</h2><span class="pill">🟢 Bot conectado</span></div>
            <div class="grid">
              <div class="card"><div class="kpi">${stats.totalTickets}</div><div class="stat-label">Tickets totales</div></div>
              <div class="card"><div class="kpi">${stats.openTickets}</div><div class="stat-label">Tickets abiertos</div></div>
              <div class="card"><div class="kpi">${stats.closedTickets}</div><div class="stat-label">Tickets cerrados</div></div>
              <div class="card"><div class="kpi">${stats.escalatedTickets}</div><div class="stat-label">Escalados a humano</div></div>
              <div class="card"><div class="kpi">${stats.totalMessages}</div><div class="stat-label">Mensajes procesados</div></div>
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

            <section id="knowledge" class="section" style="margin-top:28px">
              <div class="section-title"><h2>Knowledge Base</h2><span class="muted small">Reglas y documentación del servidor</span></div>
              <div class="card">
                <label>Mensaje de bienvenida</label>
                <textarea name="welcomeText" style="min-height:110px">${escapeHtml(cfg.welcomeText,1000)}</textarea>
                <div class="help">Aparece automáticamente cuando se abre un ticket.</div>

                <label style="margin-top:18px">Base de conocimiento</label>
                <textarea name="knowledge">${escapeHtml(cfg.knowledge,10000)}</textarea>
                <div class="help">Introduce reglas, FAQ, precios, procedimientos y documentación que la IA puede utilizar.</div>

                <div class="toolbar" style="margin-top:16px">
                  <a class="btn alt" href="/dashboard">← Volver</a>
                  <button class="btn" type="submit">💾 Guardar cambios</button>
                </div>
              </div>
            </section>
          </form>
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

app.post("/api/servers/:guildId", async (req, res) => {
  try {
    const session = currentSession(req);
    if (!session) return res.status(401).send("Sesión requerida.");

    const guild = session.guilds.find(g => g.id === req.params.guildId);
    if (!guild || !client.guilds.cache.get(guild.id)) {
      return res.status(403).send("No autorizado.");
    }

    const body = req.body || {};
    await saveGuildConfig(guild.id, {
      founderId: cleanText(body.founderId,100).trim() || config.founderId,
      staffRoleId: cleanText(body.staffRoleId,100).trim(),
      ticketCategoryId: cleanText(body.ticketCategoryId,100).trim(),
      welcomeText: cleanText(body.welcomeText,1000).trim(),
      knowledge: cleanText(body.knowledge,10000)
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
  }
};
