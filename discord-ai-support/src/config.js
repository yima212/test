require("dotenv").config();

const required = [
  "DISCORD_TOKEN",
  "CLIENT_ID",
  "GUILD_ID",
  "FOUNDER_USER_ID"
];

for (const key of required) {
  if (!process.env[key]) {
    console.warn(`[CONFIG] Falta ${key} en .env`);
  }
}

module.exports = {
  token: (process.env.DISCORD_TOKEN || "").trim().replace(/^["']|["']$/g, "").replace(/^Bot\s+/i, "").trim(),
  clientId: (process.env.CLIENT_ID || "").trim(),
  guildId: (process.env.GUILD_ID || "").trim(),
  founderId: (process.env.FOUNDER_USER_ID || "").trim(),
  ticketCategoryId: process.env.TICKET_CATEGORY_ID || null,
  staffRoleId: process.env.STAFF_ROLE_ID || null,
  geminiKey: (process.env.GEMINI_API_KEY || "").trim() || null,
  aiModel: process.env.AI_MODEL || "gemini-2.5-flash-lite"
};
