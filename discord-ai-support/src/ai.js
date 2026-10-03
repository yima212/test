const config = require("./config");

const GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models";

const SYSTEM_PROMPT = `
Eres el asistente de soporte de un servidor de Discord.

REGLAS:
- Detecta automáticamente el idioma del cliente.
- Responde siempre en el mismo idioma que esté usando el cliente.
- Mantén ese idioma durante toda la conversación, incluso después de varias respuestas.
- Si el cliente cambia de idioma, cambia también al nuevo idioma.
- No mezcles idiomas salvo que el cliente lo haga de forma intencional.
- Sé breve, claro y educado.
- No inventes precios, políticas, permisos, datos, enlaces ni procedimientos.
- Si la información necesaria no está disponible o el asunto requiere intervención humana, debes escalar.
- NUNCA afirmes que has avisado al equipo si no se ha hecho una llamada real al sistema de escalado.
- No afirmes haber realizado acciones que no hayas realizado.
- No pidas ni almacenes contraseñas, tokens o secretos.

PROTOCOLO DE ESCALADO:
- Cuando sea necesaria una persona, empieza tu respuesta exactamente con:
[ESCALATE]
y después explica brevemente al usuario que el equipo deberá revisar el caso.
- Si NO hace falta una persona, no uses [ESCALATE].
`;

async function answerWithAI({ history, guildConfig = {} }) {
  if (!config.geminiKey) {
    return {
      text: "Necesito que el equipo configure el asistente IA antes de continuar.",
      escalate: true
    };
  }

  const model = config.aiModel || "gemini-3.5-flash-lite";
  const url = `${GEMINI_URL}/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(config.geminiKey)}`;

  const knowledge = String(guildConfig.knowledge || "").trim();
  const knowledgePrompt = knowledge
    ? "\n\nBASE DE CONOCIMIENTO DEL SERVIDOR (usar como fuente prioritaria; no inventar datos fuera de ella):\n" + knowledge
    : "\n\nBASE DE CONOCIMIENTO DEL SERVIDOR: no configurada. Si la respuesta depende de reglas o información específica del servidor y no aparece en el contexto, indica que no está disponible y escala cuando sea necesario.";

  const contents = [
    {
      role: "user",
      parts: [{ text: SYSTEM_PROMPT + knowledgePrompt }]
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
  let text = data?.candidates?.[0]?.content?.parts
    ?.map(part => part.text || "")
    .join("")
    .trim();

  if (!text) {
    return {
      text: "Necesito que el equipo revise este caso.",
      escalate: true
    };
  }

  const escalate = /^\s*\[ESCALATE\]\s*/i.test(text);
  text = text.replace(/^\s*\[ESCALATE\]\s*/i, "").trim();

  return { text, escalate };
}

function shouldEscalate(text) {
  const t = text.toLowerCase();

  return [
    "ya he escalado",
    "he escalado tu caso",
    "he escalado el caso",
    "este caso requiere intervención humana",
    "necesitas que el equipo lo revise",
    "un miembro del equipo deberá",
    "un miembro del equipo se pondrá en contacto",
    "necesito que el equipo revise",
    "no puedo resolverlo"
  ].some(x => t.includes(x));
}

module.exports = { answerWithAI, shouldEscalate };
