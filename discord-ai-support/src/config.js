require("dotenv").config();

const required = [
  "DISCORD_TOKEN",
  "CLIENT_ID"
];

for (const key of required) {
  if (!process.env[key]) {
    console.warn(`[CONFIG] Falta ${key} en .env`);
  }
}

module.exports = {
  token: (process.env.DISCORD_TOKEN || "").trim().replace(/^["']|["']$/g, "").replace(/^Bot\s+/i, "").trim(),
  clientId: (process.env.CLIENT_ID || "").trim(),
  founderId: (process.env.FOUNDER_USER_ID || "").trim(),
  ticketCategoryId: process.env.TICKET_CATEGORY_ID || null,
  staffRoleId: process.env.STAFF_ROLE_ID || null,
  geminiKey: (process.env.GEMINI_API_KEY || "").trim() || null,
  aiModel: process.env.AI_MODEL || "gemini-3.5-flash-lite",
  port: Number(process.env.PORT || 3000),
  discordClientSecret: (process.env.DISCORD_CLIENT_SECRET || "").trim(),
  dashboardUrl: (process.env.DASHBOARD_URL || "https://discord-ai-support-production-7db6.up.railway.app").replace(/\/$/, ""),
  stripeSecretKey: (process.env.STRIPE_SECRET_KEY || "").trim(),
  stripeWebhookSecret: (process.env.STRIPE_WEBHOOK_SECRET || "").trim(),
  stripeProPriceId: (process.env.STRIPE_PRO_PRICE_ID || "").trim(),
  stripeLifetimePriceId: (process.env.STRIPE_LIFETIME_PRICE_ID || "").trim()
};
