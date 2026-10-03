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
  getRecentGuildTickets
};
