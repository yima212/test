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
      welcome_text TEXT NOT NULL DEFAULT 'Hola 👋 Cuéntame qué necesitas.',
      knowledge TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  console.log("✅ PostgreSQL conectado y tabla guild_configs lista.");
}

async function getGuildConfig(guildId) {
  const fallback = {
    staffRoleId: config.staffRoleId || "",
    founderId: config.founderId || "",
    welcomeText: "Hola 👋 Cuéntame qué necesitas.",
    knowledge: ""
  };

  const result = await getPool().query(
    "SELECT founder_id, staff_role_id, welcome_text, knowledge FROM guild_configs WHERE guild_id = $1",
    [guildId]
  );

  if (result.rowCount === 0) return fallback;

  const row = result.rows[0];
  return {
    staffRoleId: row.staff_role_id || "",
    founderId: row.founder_id || fallback.founderId,
    welcomeText: row.welcome_text || fallback.welcomeText,
    knowledge: row.knowledge || ""
  };
}

async function saveGuildConfig(guildId, cfg) {
  await getPool().query(
    `INSERT INTO guild_configs
      (guild_id, founder_id, staff_role_id, welcome_text, knowledge, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (guild_id)
     DO UPDATE SET
       founder_id = EXCLUDED.founder_id,
       staff_role_id = EXCLUDED.staff_role_id,
       welcome_text = EXCLUDED.welcome_text,
       knowledge = EXCLUDED.knowledge,
       updated_at = NOW()`,
    [
      guildId,
      cfg.founderId || "",
      cfg.staffRoleId || "",
      cfg.welcomeText || "",
      cfg.knowledge || ""
    ]
  );

  return cfg;
}

module.exports = {
  getPool,
  initDatabase,
  getGuildConfig,
  saveGuildConfig
};
