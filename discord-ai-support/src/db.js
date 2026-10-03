const { Pool } = require("pg");
const config = require("./config");

let pool = null;

function getPool() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL no está configurada.");
  }

  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });

    pool.on("error", error => {
      console.error("❌ Error inesperado de PostgreSQL:", error.message);
    });
  }

  return pool;
}

async function initDatabase() {
  const p = getPool();

  await p.query(`
    CREATE TABLE IF NOT EXISTS dashboard_users (
      discord_user_id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      avatar TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS dashboard_sessions (
      token TEXT PRIMARY KEY,
      discord_user_id TEXT NOT NULL REFERENCES dashboard_users(discord_user_id) ON DELETE CASCADE,
      guilds JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_expiry
    ON dashboard_sessions (expires_at)
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS oauth_states (
      state TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS guild_subscriptions (
      guild_id TEXT PRIMARY KEY,
      plan TEXT NOT NULL DEFAULT 'free',
      status TEXT NOT NULL DEFAULT 'active',
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      stripe_price_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await p.query(`
    ALTER TABLE guild_subscriptions
    ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT,
    ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT,
    ADD COLUMN IF NOT EXISTS stripe_price_id TEXT
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS guild_usage_monthly (
      guild_id TEXT NOT NULL,
      usage_month TEXT NOT NULL,
      tickets_created INTEGER NOT NULL DEFAULT 0,
      ai_responses INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (guild_id, usage_month)
    )
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_guild_usage_monthly_month
    ON guild_usage_monthly (usage_month)
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS guild_configs (
      guild_id TEXT PRIMARY KEY,
      founder_id TEXT,
      staff_role_id TEXT,
      ticket_category_id TEXT,
      welcome_text TEXT NOT NULL DEFAULT 'Hola 👋 Cuéntame qué necesitas.',
      knowledge TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await p.query(`
    ALTER TABLE guild_configs
    ADD COLUMN IF NOT EXISTS ticket_category_id TEXT
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS tickets (
      channel_id TEXT PRIMARY KEY,
      guild_id TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
      escalated BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      closed_at TIMESTAMPTZ
    )
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_tickets_guild_status
    ON tickets (guild_id, status)
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS ticket_messages (
      id BIGSERIAL PRIMARY KEY,
      channel_id TEXT NOT NULL REFERENCES tickets(channel_id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_ticket_messages_channel
    ON ticket_messages (channel_id, created_at)
  `);

  console.log("✅ PostgreSQL conectado: configuración, tickets e historial persistente listos.");

}

async function getGuildConfig(guildId) {
  const fallback = {
    staffRoleId: config.staffRoleId || "",
    ticketCategoryId: config.ticketCategoryId || "",
    founderId: config.founderId || "",
    welcomeText: "Hola 👋 Cuéntame qué necesitas.",
    knowledge: ""
  };

  const result = await getPool().query(
    "SELECT founder_id, staff_role_id, ticket_category_id, welcome_text, knowledge FROM guild_configs WHERE guild_id = $1",
    [guildId]
  );

  if (result.rowCount === 0) return fallback;

  const row = result.rows[0];
  return {
    staffRoleId: row.staff_role_id || "",
    ticketCategoryId: row.ticket_category_id || fallback.ticketCategoryId,
    founderId: row.founder_id || fallback.founderId,
    welcomeText: row.welcome_text || fallback.welcomeText,
    knowledge: row.knowledge || ""
  };
}

async function saveGuildConfig(guildId, cfg) {
  await getPool().query(
    `INSERT INTO guild_configs
      (guild_id, founder_id, staff_role_id, ticket_category_id, welcome_text, knowledge, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     ON CONFLICT (guild_id)
     DO UPDATE SET
       founder_id = EXCLUDED.founder_id,
       staff_role_id = EXCLUDED.staff_role_id,
       ticket_category_id = EXCLUDED.ticket_category_id,
       welcome_text = EXCLUDED.welcome_text,
       knowledge = EXCLUDED.knowledge,
       updated_at = NOW()`,
    [
      guildId,
      cfg.founderId || "",
      cfg.staffRoleId || "",
      cfg.ticketCategoryId || "",
      cfg.welcomeText || "",
      cfg.knowledge || ""
    ]
  );

  return cfg;
}

async function createTicket({ channelId, guildId, ownerId }) {
  await getPool().query(
    `INSERT INTO tickets (channel_id, guild_id, owner_id, status, escalated)
     VALUES ($1, $2, $3, 'open', FALSE)
     ON CONFLICT (channel_id) DO NOTHING`,
    [channelId, guildId, ownerId]
  );
}

async function addTicketMessage(channelId, role, content) {
  await getPool().query(
    `INSERT INTO ticket_messages (channel_id, role, content)
     SELECT $1, $2, $3
     WHERE EXISTS (
       SELECT 1 FROM tickets WHERE channel_id = $1
     )`,
    [channelId, role, content]
  );
}

async function setTicketEscalated(channelId, escalated) {
  await getPool().query(
    "UPDATE tickets SET escalated = $2 WHERE channel_id = $1",
    [channelId, escalated]
  );
}

async function closeTicket(channelId) {
  await getPool().query(
    `UPDATE tickets
     SET status = 'closed', closed_at = NOW()
     WHERE channel_id = $1`,
    [channelId]
  );
}

async function loadOpenTickets() {
  const result = await getPool().query(
    `SELECT
       t.channel_id,
       t.guild_id,
       t.owner_id,
       t.escalated,
       COALESCE(
         json_agg(
           json_build_object(
             'role', tm.role,
             'content', tm.content,
             'createdAt', tm.created_at
           )
           ORDER BY tm.created_at ASC
         ) FILTER (WHERE tm.id IS NOT NULL),
         '[]'::json
       ) AS history
     FROM tickets t
     LEFT JOIN ticket_messages tm ON tm.channel_id = t.channel_id
     WHERE t.status = 'open'
     GROUP BY t.channel_id, t.guild_id, t.owner_id, t.escalated
     ORDER BY t.created_at ASC`
  );

  return result.rows.map(row => ({
    channelId: row.channel_id,
    guildId: row.guild_id,
    ownerId: row.owner_id,
    escalated: Boolean(row.escalated),
    history: Array.isArray(row.history) ? row.history.map(item => ({
      role: item.role,
      content: item.content
    })) : []
  }));
}

async function upsertDashboardUser(user) {
  await getPool().query(
    `INSERT INTO dashboard_users (discord_user_id, username, avatar, created_at, last_login_at)
     VALUES ($1, $2, $3, NOW(), NOW())
     ON CONFLICT (discord_user_id)
     DO UPDATE SET
       username = EXCLUDED.username,
       avatar = EXCLUDED.avatar,
       last_login_at = NOW()`,
    [user.id, user.username || "Discord User", user.avatar || null]
  );
}

async function createDashboardSession({ token, user, guilds, expiresAt }) {
  await upsertDashboardUser(user);
  await getPool().query(
    `INSERT INTO dashboard_sessions
      (token, discord_user_id, guilds, expires_at)
     VALUES ($1, $2, $3::jsonb, $4)`,
    [token, user.id, JSON.stringify(guilds || []), expiresAt]
  );
}

async function getDashboardSession(token) {
  const result = await getPool().query(
    `SELECT
       s.token,
       s.discord_user_id,
       s.guilds,
       s.expires_at,
       u.username,
       u.avatar
     FROM dashboard_sessions s
     INNER JOIN dashboard_users u ON u.discord_user_id = s.discord_user_id
     WHERE s.token = $1
       AND s.expires_at > NOW()`,
    [token]
  );

  if (result.rowCount === 0) return null;

  return {
    token: result.rows[0].token,
    user: {
      id: result.rows[0].discord_user_id,
      username: result.rows[0].username,
      avatar: result.rows[0].avatar
    },
    guilds: Array.isArray(result.rows[0].guilds)
      ? result.rows[0].guilds
      : [],
    createdAt: null
  };
}

async function deleteDashboardSession(token) {
  await getPool().query(
    "DELETE FROM dashboard_sessions WHERE token = $1",
    [token]
  );
}

async function createOAuthState(state, expiresAt) {
  await getPool().query(
    `INSERT INTO oauth_states (state, expires_at)
     VALUES ($1, $2)`,
    [state, expiresAt]
  );
}

async function consumeOAuthState(state) {
  const result = await getPool().query(
    `DELETE FROM oauth_states
     WHERE state = $1
       AND expires_at > NOW()
     RETURNING state`,
    [state]
  );
  return result.rowCount > 0;
}

async function cleanupExpiredSessions() {
  await getPool().query("DELETE FROM dashboard_sessions WHERE expires_at <= NOW()");
  await getPool().query("DELETE FROM oauth_states WHERE expires_at <= NOW()");
}

async function getGuildPlan(guildId) {
  const result = await getPool().query(
    "SELECT plan, status, stripe_customer_id, stripe_subscription_id, stripe_price_id FROM guild_subscriptions WHERE guild_id = $1",
    [guildId]
  );

  if (result.rowCount === 0) {
    await getPool().query(
      `INSERT INTO guild_subscriptions (guild_id, plan, status)
       VALUES ($1, 'free', 'active')
       ON CONFLICT (guild_id) DO NOTHING`,
      [guildId]
    );
    return {
      plan: "free",
      status: "active",
      stripeCustomerId: null,
      stripeSubscriptionId: null,
      stripePriceId: null
    };
  }

  const row = result.rows[0];
  return {
    plan: row.plan,
    status: row.status,
    stripeCustomerId: row.stripe_customer_id || null,
    stripeSubscriptionId: row.stripe_subscription_id || null,
    stripePriceId: row.stripe_price_id || null
  };
}

async function saveGuildSubscription({
  guildId,
  plan,
  status,
  stripeCustomerId = null,
  stripeSubscriptionId = null,
  stripePriceId = null
}) {
  await getPool().query(
    `INSERT INTO guild_subscriptions
      (guild_id, plan, status, stripe_customer_id, stripe_subscription_id, stripe_price_id, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     ON CONFLICT (guild_id)
     DO UPDATE SET
       plan = EXCLUDED.plan,
       status = EXCLUDED.status,
       stripe_customer_id = EXCLUDED.stripe_customer_id,
       stripe_subscription_id = EXCLUDED.stripe_subscription_id,
       stripe_price_id = EXCLUDED.stripe_price_id,
       updated_at = NOW()`,
    [guildId, plan, status, stripeCustomerId, stripeSubscriptionId, stripePriceId]
  );

  return getGuildPlan(guildId);
}

async function getGuildUsage(guildId) {
  const result = await getPool().query(
    `SELECT
       COALESCE((
         SELECT COUNT(*)::int
         FROM tickets
         WHERE guild_id = $1
           AND created_at >= date_trunc('month', NOW() AT TIME ZONE 'Europe/Madrid') AT TIME ZONE 'Europe/Madrid'
           AND created_at < (date_trunc('month', NOW() AT TIME ZONE 'Europe/Madrid') + INTERVAL '1 month') AT TIME ZONE 'Europe/Madrid'
       ), 0) AS tickets_created,
       COALESCE((
         SELECT ai_responses
         FROM guild_usage_monthly
         WHERE guild_id = $1
           AND usage_month = to_char(NOW() AT TIME ZONE 'Europe/Madrid', 'YYYY-MM')
       ), 0)::int AS ai_responses`,
    [guildId]
  );

  const row = result.rows[0] || {};
  return {
    ticketsCreated: Number(row.tickets_created || 0),
    aiResponses: Number(row.ai_responses || 0),
    month: new Intl.DateTimeFormat("en-CA", {
      timeZone: "Europe/Madrid",
      year: "numeric",
      month: "2-digit"
    }).format(new Date())
  };
}

async function consumeGuildQuota(guildId, metric, limit) {
  const column = metric === "ai" ? "ai_responses" : metric === "tickets" ? "tickets_created" : null;
  if (!column) throw new Error("Métrica de cuota no válida.");

  const safeLimit = Math.max(0, Number(limit) || 0);
  if (safeLimit === 0) return false;

  const p = getPool();

  if (metric === "tickets") {
    const result = await p.query(
      `SELECT COUNT(*)::int AS count
       FROM tickets
       WHERE guild_id = $1
         AND created_at >= date_trunc('month', NOW() AT TIME ZONE 'Europe/Madrid') AT TIME ZONE 'Europe/Madrid'
         AND created_at < (date_trunc('month', NOW() AT TIME ZONE 'Europe/Madrid') + INTERVAL '1 month') AT TIME ZONE 'Europe/Madrid'`,
      [guildId]
    );
    return Number(result.rows[0]?.count || 0) < safeLimit;
  }

  await p.query(
    `INSERT INTO guild_usage_monthly (guild_id, usage_month, ai_responses)
     VALUES ($1, to_char(NOW() AT TIME ZONE 'Europe/Madrid', 'YYYY-MM'), 0)
     ON CONFLICT (guild_id, usage_month)
     DO NOTHING`,
    [guildId]
  );

  const result = await p.query(
    `UPDATE guild_usage_monthly
     SET ai_responses = ai_responses + 1, updated_at = NOW()
     WHERE guild_id = $1
       AND usage_month = to_char(NOW() AT TIME ZONE 'Europe/Madrid', 'YYYY-MM')
       AND ai_responses < $2
     RETURNING ai_responses`,
    [guildId, safeLimit]
  );

  return result.rowCount > 0;
}

async function releaseGuildQuota(guildId, metric) {
  if (metric !== "ai") return;

  await getPool().query(
    `UPDATE guild_usage_monthly
     SET ai_responses = GREATEST(ai_responses - 1, 0), updated_at = NOW()
     WHERE guild_id = $1
       AND usage_month = to_char(NOW() AT TIME ZONE 'Europe/Madrid', 'YYYY-MM')`,
    [guildId]
  );
}

async function getGuildDashboardStats(guildId) {
  const result = await getPool().query(
    `SELECT
       COUNT(*)::int AS total_tickets,
       COUNT(*) FILTER (WHERE status = 'open')::int AS open_tickets,
       COUNT(*) FILTER (WHERE status = 'closed')::int AS closed_tickets,
       COUNT(*) FILTER (WHERE escalated = TRUE)::int AS escalated_tickets,
       COALESCE((
         SELECT COUNT(*)::int
         FROM ticket_messages tm
         INNER JOIN tickets t2 ON t2.channel_id = tm.channel_id
         WHERE t2.guild_id = $1
       ), 0) AS total_messages
     FROM tickets
     WHERE guild_id = $1`,
    [guildId]
  );

  const row = result.rows[0];
  return {
    totalTickets: row?.total_tickets || 0,
    openTickets: row?.open_tickets || 0,
    closedTickets: row?.closed_tickets || 0,
    escalatedTickets: row?.escalated_tickets || 0,
    totalMessages: row?.total_messages || 0
  };
}

async function getRecentGuildTickets(guildId, limit = 10) {
  const safeLimit = Math.min(Math.max(Number(limit) || 10, 1), 50);
  const result = await getPool().query(
    `SELECT
       channel_id,
       owner_id,
       status,
       escalated,
       created_at,
       closed_at
     FROM tickets
     WHERE guild_id = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [guildId, safeLimit]
  );

  return result.rows;
}

module.exports = {
  getPool,
  initDatabase,
  getGuildConfig,
  saveGuildConfig,
  createTicket,
  addTicketMessage,
  setTicketEscalated,
  closeTicket,
  loadOpenTickets,
  getGuildDashboardStats,
  getRecentGuildTickets,
  upsertDashboardUser,
  createDashboardSession,
  getDashboardSession,
  deleteDashboardSession,
  createOAuthState,
  consumeOAuthState,
  cleanupExpiredSessions,
  getGuildPlan,
  saveGuildSubscription,
  getGuildUsage,
  consumeGuildQuota,
  releaseGuildQuota
};
