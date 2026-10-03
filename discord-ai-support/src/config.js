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
  token: process.env.DISCORD_TOKEN,
  clientId: process.env.CLIENT_ID,
  guildId: process.env.GUILD_ID,
  founderId: process.env.FOUNDER_USER_ID,
  ticketCategoryId: process.env.TICKET_CATEGORY_ID || null,
  staffRoleId: process.env.STAFF_ROLE_ID || null,
  openaiKey: process.env.OPENAI_API_KEY || null,
  aiModel: process.env.AI_MODEL || "gpt-5.6"
};
