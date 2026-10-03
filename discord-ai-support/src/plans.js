const PLAN_DEFINITIONS = {
  free: {
    key: "free",
    name: "Starter",
    price: "$0",
    billing: "Sin coste",
    ticketsPerMonth: 50,
    aiRepliesPerMonth: 100,
    knowledgeChars: 10000,
    features: [
      "Tickets privados",
      "Asistente IA multilingüe",
      "Escalado a humano",
      "Dashboard por servidor"
    ]
  },
  pro: {
    key: "pro",
    name: "Pro",
    price: "$6",
    billing: "por mes",
    ticketsPerMonth: 500,
    aiRepliesPerMonth: 2000,
    knowledgeChars: 50000,
    features: [
      "Todo lo de Starter",
      "Hasta 500 tickets nuevos/mes",
      "Hasta 2.000 respuestas IA/mes",
      "Knowledge Base de hasta 50.000 caracteres"
    ]
  },
  lifetime: {
    key: "lifetime",
    name: "Lifetime",
    price: "$30",
    billing: "pago único",
    ticketsPerMonth: 2000,
    aiRepliesPerMonth: 10000,
    knowledgeChars: 100000,
    features: [
      "Todo lo de Pro",
      "Hasta 2.000 tickets nuevos/mes",
      "Hasta 10.000 respuestas IA/mes",
      "Knowledge Base de hasta 100.000 caracteres",
      "Sin renovación mensual"
    ]
  }
};

function normalizePlan(plan) {
  const key = String(plan || "free").toLowerCase();
  return PLAN_DEFINITIONS[key] ? key : "free";
}

function getPlanDefinition(plan) {
  return PLAN_DEFINITIONS[normalizePlan(plan)];
}

function formatLimit(value, unit) {
  if (!Number.isFinite(value)) return "Sin límite";
  return new Intl.NumberFormat("es-ES").format(value) + (unit ? " " + unit : "");
}

module.exports = {
  PLAN_DEFINITIONS,
  normalizePlan,
  getPlanDefinition,
  formatLimit
};
