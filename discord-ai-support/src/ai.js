const config = require("./config");

const GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models";

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
  if (!config.geminiKey) {
    return {
      text: "👤 El asistente IA no está configurado todavía. He avisado al equipo.",
      escalate: true
    };
  }

  const model = config.aiModel || "gemini-2.5-flash-lite";
  const url = `${GEMINI_URL}/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(config.geminiKey)}`;

  const contents = [
    {
      role: "user",
      parts: [{ text: SYSTEM_PROMPT }]
    },
    ...history.map(m => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }]
    }))
  ];

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents,
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 500
      }
    })
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Gemini API ${response.status}: ${body}`);
  }

  const data = await response.json();
  const text = data?.candidates?.[0]?.content?.parts
    ?.map(part => part.text || "")
    .join("")
    .trim();

  return {
    text: text || "👤 Necesito que el equipo revise este caso.",
    escalate: !text
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
