const OpenAI = require("openai");
const config = require("./config");

const client = config.openaiKey
  ? new OpenAI({ apiKey: config.openaiKey })
  : null;

const SYSTEM_PROMPT = `
Eres el asistente de soporte de un servidor de Discord.

REGLAS:
- Responde en español salvo que el usuario escriba claramente en otro idioma.
- Sé breve, claro y educado.
- No inventes precios, políticas, permisos, datos, enlaces ni procedimientos.
- Si la información necesaria no está disponible, debes ESCALAR.
- No afirmes haber realizado acciones que no hayas realizado.
- No pidas ni almacenes contraseñas, tokens o secretos.
- Si el asunto requiere intervención humana, indícalo.
`;

async function answerWithAI({ history }) {
  if (!client) {
    return {
      text: "👤 No puedo responder todavía porque el agente IA no está configurado. He avisado al equipo.",
      escalate: true
    };
  }

  const response = await client.responses.create({
    model: config.aiModel,
    instructions: SYSTEM_PROMPT,
    input: history.map(m => ({ role: m.role, content: m.content }))
  });

  return {
    text: response.output_text?.trim() || "👤 Necesito que el equipo revise este caso.",
    escalate: !response.output_text
  };
}

function shouldEscalate(text) {
  const t = text.toLowerCase();
  return [
    "no tengo información suficiente",
    "necesito que el equipo",
    "que el equipo lo revise",
    "no puedo resolver"
  ].some(x => t.includes(x));
}

module.exports = { answerWithAI, shouldEscalate };
