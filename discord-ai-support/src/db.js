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
    CREATE TABLE IF NOT EXISTS activation_codes (
      code_hash TEXT PRIMARY KEY,
      code_hint TEXT NOT NULL,
      plan TEXT NOT NULL CHECK (plan IN ('pro', 'lifetime')),
      status TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'used', 'disabled')),
      created_by_discord_user_id TEXT NOT NULL,
      expires_at TIMESTAMPTZ,
      redeemed_guild_id TEXT,
      redeemed_by_discord_user_id TEXT,
      redeemed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_activation_codes_status_created
    ON activation_codes (status, created_at DESC)
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_activation_codes_redeemed_guild
    ON activation_codes (redeemed_guild_id)
  `);


  await p.query(`
    CREATE TABLE IF NOT EXISTS admin_audit_log (
      id BIGSERIAL PRIMARY KEY,
      actor_discord_user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      guild_id TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created
    ON admin_audit_log (created_at DESC)
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


function normalizeActivationCode(code) {
  return String(code || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");
}

function hashActivationCode(code) {
  return require("crypto")
    .createHash("sha256")
    .update(normalizeActivationCode(code))
    .digest("hex");
}

function activationCodeCharacters() {
  return "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
}

function randomActivationPart(length = 4) {
  const chars = activationCodeCharacters();
  let value = "";
  for (let i = 0; i < length; i += 1) {
    value += chars[require("crypto").randomInt(0, chars.length)];
  }
  return value;
}

function buildActivationCode(plan) {
  const prefix = plan === "lifetime" ? "LIFE" : "PRO";
  return prefix + "-" + randomActivationPart(4) + "-" + randomActivationPart(4);
}

async function createActivationCodes({ plan, quantity, expiresAt = null, createdByDiscordUserId }) {
  if (!["pro", "lifetime"].includes(plan)) {
    throw new Error("Plan de activación no válido.");
  }

  const safeQuantity = Math.min(Math.max(Number(quantity) || 0, 1), 100);
  if (safeQuantity < 1) {
    throw new Error("La cantidad de códigos no es válida.");
  }

  if (!createdByDiscordUserId) {
    throw new Error("Falta el usuario creador del lote.");
  }

  let expiration = null;
  if (expiresAt) {
    const parsed = new Date(expiresAt);
    if (Number.isNaN(parsed.getTime())) {
      throw new Error("La fecha de expiración no es válida.");
    }
    if (parsed.getTime() <= Date.now()) {
      throw new Error("La fecha de expiración debe ser futura.");
    }
    expiration = parsed.toISOString();
  }

  const p = getPool();
  const client = await p.connect();
  const createdCodes = [];

  try {
    await client.query("BEGIN");

    const usedHashes = new Set();

    while (createdCodes.length < safeQuantity) {
      const rawCode = buildActivationCode(plan);
      const codeHash = hashActivationCode(rawCode);

      if (usedHashes.has(codeHash)) continue;
      usedHashes.add(codeHash);

      try {
        await client.query(
          `INSERT INTO activation_codes
            (code_hash, code_hint, plan, status, created_by_discord_user_id, expires_at)
           VALUES ($1, $2, $3, 'available', $4, $5)`,
          [
            codeHash,
            rawCode.split("-").slice(0, 2).join("-"),
            plan,
            createdByDiscordUserId,
            expiration
          ]
        );
        createdCodes.push(rawCode);
      } catch (error) {
        if (error.code === "23505") continue;
        throw error;
      }
    }

    await client.query("COMMIT");
    return createdCodes;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function redeemActivationCode({ code, guildId, discordUserId }) {
  const normalized = normalizeActivationCode(code);
  if (!normalized || !guildId || !discordUserId) {
    return { ok: false, reason: "invalid" };
  }

  const codeHash = hashActivationCode(normalized);
  const p = getPool();
  const client = await p.connect();

  try {
    await client.query("BEGIN");

    const codeResult = await client.query(
      `SELECT
         code_hash,
         plan,
         status,
         expires_at
       FROM activation_codes
       WHERE code_hash = $1
       FOR UPDATE`,
      [codeHash]
    );

    if (codeResult.rowCount === 0) {
      await client.query("ROLLBACK");
      return { ok: false, reason: "invalid" };
    }

    const activation = codeResult.rows[0];

    if (activation.status !== "available") {
      await client.query("ROLLBACK");
      return {
        ok: false,
        reason: activation.status === "used" ? "used" : "disabled"
      };
    }

    if (activation.expires_at && new Date(activation.expires_at).getTime() <= Date.now()) {
      await client.query(
        `UPDATE activation_codes
         SET status = 'disabled'
         WHERE code_hash = $1`,
        [codeHash]
      );
      await client.query("COMMIT");
      return { ok: false, reason: "expired" };
    }

    const subscriptionResult = await client.query(
      `SELECT plan, status
       FROM guild_subscriptions
       WHERE guild_id = $1
       FOR UPDATE`,
      [guildId]
    );

    if (subscriptionResult.rowCount > 0) {
      const current = subscriptionResult.rows[0];
      const currentPlan = String(current.plan || "free").toLowerCase();
      const currentStatus = String(current.status || "active").toLowerCase();

      if (currentStatus === "active" && currentPlan !== "free") {
        await client.query("ROLLBACK");
        return { ok: false, reason: "plan_active" };
      }
    }

    await client.query(
      `INSERT INTO guild_subscriptions
        (guild_id, plan, status, stripe_customer_id, stripe_subscription_id, stripe_price_id, updated_at)
       VALUES ($1, $2, 'active', NULL, NULL, NULL, NOW())
       ON CONFLICT (guild_id)
       DO UPDATE SET
         plan = EXCLUDED.plan,
         status = 'active',
         stripe_customer_id = NULL,
         stripe_subscription_id = NULL,
         stripe_price_id = NULL,
         updated_at = NOW()`,
      [guildId, activation.plan]
    );

    const redeemed = await client.query(
      `UPDATE activation_codes
       SET
         status = 'used',
         redeemed_guild_id = $2,
         redeemed_by_discord_user_id = $3,
         redeemed_at = NOW()
       WHERE code_hash = $1
         AND status = 'available'
       RETURNING plan`,
      [codeHash, guildId, discordUserId]
    );

    if (redeemed.rowCount !== 1) {
      await client.query("ROLLBACK");
      return { ok: false, reason: "used" };
    }

    await client.query("COMMIT");
    return { ok: true, plan: redeemed.rows[0].plan };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Activation code redeem error:", error);
    throw error;
  } finally {
    client.release();
  }
}

async function disableActivationCode(code) {
  const normalized = normalizeActivationCode(code);
  if (!normalized) return false;

  const result = await getPool().query(
    `UPDATE activation_codes
     SET status = 'disabled'
     WHERE code_hash = $1
       AND status = 'available'
     RETURNING code_hint`,
    [hashActivationCode(normalized)]
  );

  return result.rowCount > 0;
}

async function listActivationCodes(limit = 100) {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const result = await getPool().query(
    `SELECT
       code_hint,
       plan,
       CASE
         WHEN status = 'available' AND expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired'
         ELSE status
       END AS status,
       expires_at,
       redeemed_guild_id,
       redeemed_by_discord_user_id,
       redeemed_at,
       created_at
     FROM activation_codes
     ORDER BY created_at DESC
     LIMIT $1`,
    [safeLimit]
  );

  return result.rows;
}

async function getActivationCodeStats() {
  const result = await getPool().query(
    `SELECT
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE status = 'available' AND (expires_at IS NULL OR expires_at > NOW()))::int AS available,
       COUNT(*) FILTER (WHERE status = 'used')::int AS used,
       COUNT(*) FILTER (WHERE status = 'disabled' OR (status = 'available' AND expires_at IS NOT NULL AND expires_at <= NOW()))::int AS disabled_or_expired
     FROM activation_codes`
  );

  const row = result.rows[0] || {};
  return {
    total: Number(row.total || 0),
    available: Number(row.available || 0),
    used: Number(row.used || 0),
    disabledOrExpired: Number(row.disabled_or_expired || 0)
  };
}


async function recordAuditLog({ actorDiscordUserId, action, guildId = null, details = {} }) {
  if (!actorDiscordUserId || !action) return;

  await getPool().query(
    `INSERT INTO admin_audit_log
      (actor_discord_user_id, action, guild_id, details)
     VALUES ($1, $2, $3, $4::jsonb)`,
    [
      actorDiscordUserId,
      String(action).slice(0, 120),
      guildId ? String(guildId).slice(0, 64) : null,
      JSON.stringify(details || {})
    ]
  );
}

async function getRecentAuditLogs(limit = 100) {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const result = await getPool().query(
    `SELECT
       id,
       actor_discord_user_id,
       action,
       guild_id,
       details,
       created_at
     FROM admin_audit_log
     ORDER BY created_at DESC
     LIMIT $1`,
    [safeLimit]
  );
  return result.rows;
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

async function getGuildTicketActivity(guildId, days = 30) {
  const safeDays = Math.min(Math.max(Number(days) || 30, 7), 90);
  const result = await getPool().query(
    `WITH days AS (
       SELECT generate_series(
         CURRENT_DATE - ($2::int - 1),
         CURRENT_DATE,
         INTERVAL '1 day'
       )::date AS day
     )
     SELECT
       d.day,
       COUNT(t.channel_id)::int AS tickets,
       COUNT(t.channel_id) FILTER (WHERE t.status = 'open')::int AS opened,
       COUNT(t.channel_id) FILTER (WHERE t.status = 'closed')::int AS closed,
       COUNT(t.channel_id) FILTER (WHERE t.escalated = TRUE)::int AS escalated
     FROM days d
     LEFT JOIN tickets t
       ON t.guild_id = $1
      AND (t.created_at AT TIME ZONE 'Europe/Madrid')::date = d.day
     GROUP BY d.day
     ORDER BY d.day ASC`,
    [guildId, safeDays]
  );

  return result.rows.map(row => ({
    day: row.day,
    tickets: Number(row.tickets || 0),
    opened: Number(row.opened || 0),
    closed: Number(row.closed || 0),
    escalated: Number(row.escalated || 0)
  }));
}

async function getGuildTicketTypeStats(guildId) {
  const result = await getPool().query(
    `WITH first_messages AS (
       SELECT DISTINCT ON (channel_id)
         channel_id,
         content
       FROM ticket_messages
       WHERE role = 'user'
       ORDER BY channel_id, created_at ASC
     ), classified AS (
       SELECT
         CASE
           WHEN LOWER(COALESCE(f.content, '')) ~ '(refund|reembolso|cobro|pago|billing|factura)' THEN 'Facturación'
           WHEN LOWER(COALESCE(f.content, '')) ~ '(report|reporte|bug|error|fallo|denuncia)' THEN 'Reportes'
           WHEN LOWER(COALESCE(f.content, '')) ~ '(como|cómo|duda|pregunta|ayuda|what|how)' THEN 'Dudas'
           ELSE 'Soporte'
         END AS ticket_type
       FROM tickets t
       LEFT JOIN first_messages f ON f.channel_id = t.channel_id
       WHERE t.guild_id = $1
     )
     SELECT ticket_type, COUNT(*)::int AS total
     FROM classified
     GROUP BY ticket_type
     ORDER BY total DESC, ticket_type ASC`,
    [guildId]
  );
  return result.rows.map(row => ({ type: row.ticket_type, total: Number(row.total || 0) }));
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
  getGuildTicketTypeStats,
  getGuildTicketActivity,
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
  releaseGuildQuota,
  normalizeActivationCode,
  createActivationCodes,
  redeemActivationCode,
  disableActivationCode,
  listActivationCodes,
  getActivationCodeStats,
  recordAuditLog,
  getRecentAuditLogs
};
