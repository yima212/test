const {
  Client,
  GatewayIntentBits,
  Partials,
  ChannelType,
  PermissionFlagsBits,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  REST,
  Routes,
  SlashCommandBuilder
} = require("discord.js");

const config = require("./config");
const { answerWithAI, shouldEscalate } = require("./ai");
const { startDashboard } = require("./web");
const { initDatabase, getGuildConfig } = require("./db");

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel]
});

const sessions = new Map();

function ticketPanel() {
  const embed = new EmbedBuilder()
    .setTitle("🎫 Soporte")
    .setDescription(
      "¿Necesitas ayuda? Pulsa el botón de abajo para abrir un ticket.\n\n" +
      "🤖 Nuestro asistente IA intentará ayudarte automáticamente."
    );

  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("ticket_open")
      .setLabel("Abrir ticket")
      .setEmoji("🎫")
      .setStyle(ButtonStyle.Primary)
  );

  return { embeds: [embed], components: [row] };
}

client.once("ready", async () => {
  console.log(`✅ Conectado como ${client.user.tag}`);

  try {
    const rest = new REST({ version: "10" }).setToken(config.token);

    const commands = [
      new SlashCommandBuilder()
        .setName("panel")
        .setDescription("Publica el panel para abrir tickets")
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild.bitfield)
        .toJSON()
    ];

    await rest.put(
      Routes.applicationGuildCommands(config.clientId, config.guildId),
      { body: commands }
    );

    console.log("✅ /panel registrado automáticamente.");
  } catch (error) {
    console.error("❌ No se pudo registrar /panel:", error);
  }

  console.log("✅ Sistema de tickets listo.");
});

const STAFF_ROLE_KEYWORDS = [
  "staff", "moderador", "moderadora", "moderator", "mod",
  "admin", "administrador", "support", "soporte"
];

function hasStaffRole(member, guildConfig = null) {
  if (!member) return false;
  if (guildConfig?.staffRoleId && member.roles.cache.has(guildConfig.staffRoleId)) return true;
  if (member.permissions.has(PermissionFlagsBits.ManageChannels)) return true;
  return member.roles.cache.some(role => {
    const name = role.name.toLowerCase();
    return STAFF_ROLE_KEYWORDS.some(keyword => name.includes(keyword));
  });
}

function getCurrentSpainTime() {
  return new Intl.DateTimeFormat("es-ES", {
    timeZone: "Europe/Madrid",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(new Date());
}

function textLooksLikeTimeQuestion(text) {
  return /(?:^|\s)(?:que|qué)\s+hora\s+(?:es|tenemos)\b/i.test(text) ||
    /\bhora\s+(?:actual|ahora)\b/i.test(text) ||
    /\bque hora\b/i.test(text) ||
    /\bqué hora\b/i.test(text);
}

function textLooksLikeFounderQuestion(text) {
  return /\b(?:quien|quién)\s+(?:es|seria|sería)\s+(?:el\s+)?fundador\b/i.test(text) ||
    /\b(?:quien|quién)\s+es\s+(?:el\s+)?owner\b/i.test(text);
}

function textLooksLikeHumanContactRequest(text) {
  return /\b(?:quiero|puedo|puedes|me\s+puedes|necesito)\b.*\b(?:hablar|contactar|llamar)\b/i.test(text) ||
    /\b(?:hablar|contactar|llamar)\b.*\b(?:staff|moderador|moderadora|moderator|admin|soporte)\b/i.test(text) ||
    /\b(?:conecta(?:me)?|ponerme\s+en\s+contacto)\b.*\b(?:staff|moderador|moderadora|moderator|admin|soporte)\b/i.test(text);
}

async function findStaffMember(guild, guildConfig) {
  if (guildConfig.staffRoleId) {
    const role = guild.roles.cache.get(guildConfig.staffRoleId);
    const member = role?.members.find(m => !m.user.bot);
    if (member) return member;
  }

  return guild.members.cache.find(
    member => !member.user.bot && hasStaffRole(member)
  ) || null;
}

async function notifyStaffMember({ member, channel, session, requestedBy }) {
  const dmMessage =
    "🛎️ **Solicitud de soporte humano**\n\n" +
    "👤 **Usuario:** <@" + session.ownerId + ">\n" +
    "🎫 **Ticket:** " + channel.toString() + "\n" +
    "📌 **Solicitud:** " + requestedBy + "\n\n" +
    "🔗 " + channel.url;

  let dmSent = false;
  try {
    await member.send(dmMessage);
    dmSent = true;
  } catch (error) {
    console.error("No se pudo enviar DM a " + member.user.tag + ":", error.message);
  }

  await channel.send({
    content: member.toString() + " 👤 Te están solicitando en este ticket.",
    allowedMentions: { users: [member.id] }
  });

  return dmSent;
}

async function handleDirectRequest(message, session) {
  const text = message.content.trim();
  const guildConfig = await getGuildConfig(message.guild.id);

  if (textLooksLikeTimeQuestion(text)) {
    await message.channel.send(
      "🕐 En España (hora peninsular) son las **" + getCurrentSpainTime() + "**."
    );
    return true;
  }

  if (textLooksLikeFounderQuestion(text)) {
    if (!guildConfig.founderId) {
      await message.channel.send("⚠️ No tengo configurado quién es el fundador.");
      return true;
    }

    await message.channel.send(
      "👑 El fundador es <@" + guildConfig.founderId + ">."
    );
    return true;
  }

  const mentionedMember = message.mentions.members.first();
  const wantsHuman = textLooksLikeHumanContactRequest(text);

  if (mentionedMember && wantsHuman) {
    if (!hasStaffRole(mentionedMember, guildConfig)) {
      await message.channel.send(
        "⚠️ " + mentionedMember.toString() + " no está identificado como miembro del staff/moderación."
      );
      return true;
    }

    const dmSent = await notifyStaffMember({
      member: mentionedMember,
      channel: message.channel,
      session,
      requestedBy: message.content
    });

    await message.channel.send(
      dmSent
        ? "✅ Vale. He contactado con " + mentionedMember.toString() + "."
        : "✅ He avisado a " + mentionedMember.toString() + " en el ticket, pero no he podido enviarle un DM."
    );
    session.escalated = true;
    return true;
  }

  if (wantsHuman) {
    const staffMember = await findStaffMember(message.guild, guildConfig);

    if (!staffMember) {
      if (guildConfig.founderId) {
        const founder = await client.users.fetch(guildConfig.founderId);
        await founder.send(
          "🛎️ **Solicitud de staff**\n\n" +
          "👤 **Usuario:** <@" + session.ownerId + ">\n" +
          "🎫 **Ticket:** " + message.channel.toString() + "\n" +
          "🔗 " + message.channel.url
        );

        await message.channel.send(
          "👤 No he encontrado un miembro del staff disponible. He avisado al fundador."
        );
        session.escalated = true;
        return true;
      }

      await message.channel.send("⚠️ No he encontrado ningún miembro del staff configurado.");
      return true;
    }

    const dmSent = await notifyStaffMember({
      member: staffMember,
      channel: message.channel,
      session,
      requestedBy: message.content
    });

    await message.channel.send(
      dmSent
        ? "✅ Vale. He contactado con " + staffMember.toString() + "."
        : "✅ He avisado a " + staffMember.toString() + " en el ticket, pero no he podido enviarle un DM."
    );
    session.escalated = true;
    return true;
  }

  return false;
}
client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand() && !interaction.isButton()) return;

  if (interaction.isChatInputCommand() && interaction.commandName === "panel") {
    if (!interaction.memberPermissions.has(PermissionFlagsBits.ManageGuild)) {
      return interaction.reply({ content: "❌ No tienes permisos.", ephemeral: true });
    }
    await interaction.channel.send(ticketPanel());
    return interaction.reply({ content: "✅ Panel publicado.", ephemeral: true });
  }

  if (!interaction.isButton()) return;

  if (interaction.customId === "ticket_open") {
    const guild = interaction.guild;
    const existing = guild.channels.cache.find(
      c => c.topic === `ticket-owner:${interaction.user.id}`
    );

    if (existing) {
      return interaction.reply({
        content: `Ya tienes un ticket abierto: ${existing}`,
        ephemeral: true
      });
    }

    const guildConfig = await getGuildConfig(guild.id);
    const permissionOverwrites = [
      {
        id: guild.roles.everyone.id,
        deny: [PermissionFlagsBits.ViewChannel]
      },
      {
        id: interaction.user.id,
        allow: [
          PermissionFlagsBits.ViewChannel,
          PermissionFlagsBits.SendMessages,
          PermissionFlagsBits.ReadMessageHistory
        ]
      },
      {
        id: client.user.id,
        allow: [
          PermissionFlagsBits.ViewChannel,
          PermissionFlagsBits.SendMessages,
          PermissionFlagsBits.ReadMessageHistory,
          PermissionFlagsBits.ManageChannels
        ]
      }
    ];

    if (guildConfig.staffRoleId) {
      permissionOverwrites.push({
        id: guildConfig.staffRoleId,
        allow: [
          PermissionFlagsBits.ViewChannel,
          PermissionFlagsBits.SendMessages,
          PermissionFlagsBits.ReadMessageHistory
        ]
      });
    }

    const channel = await guild.channels.create({
      name: `ticket-${interaction.user.username}`.toLowerCase().slice(0, 90),
      type: ChannelType.GuildText,
      parent: config.ticketCategoryId || undefined,
      topic: `ticket-owner:${interaction.user.id}`,
      permissionOverwrites
    });

    sessions.set(channel.id, {
      ownerId: interaction.user.id,
      history: [],
      escalated: false
    });

    const closeRow = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("ticket_close")
        .setLabel("Cerrar ticket")
        .setEmoji("🔒")
        .setStyle(ButtonStyle.Danger),
      new ButtonBuilder()
        .setCustomId("ticket_human")
        .setLabel("Hablar con humano")
        .setEmoji("👤")
        .setStyle(ButtonStyle.Secondary)
    );

    await channel.send({
      content: `<@${interaction.user.id}>`,
      embeds: [
        new EmbedBuilder()
          .setTitle("🤖 Asistente de soporte")
          .setDescription(
            guildConfig.welcomeText ||
            "Hola 👋 Cuéntame qué necesitas. Intentaré ayudarte.\n\n" +
            "Si no puedo resolverlo con seguridad, avisaré al equipo."
          )
      ],
      components: [closeRow]
    });

    return interaction.reply({
      content: `✅ Ticket creado: ${channel}`,
      ephemeral: true
    });
  }

  if (interaction.customId === "ticket_human") {
    const session = sessions.get(interaction.channel.id) || {
      ownerId: interaction.user.id,
      history: [],
      escalated: false
    };
    sessions.set(interaction.channel.id, session);

    try {
      const sent = await escalateToFounder(
        interaction.channel,
        session,
        "El usuario solicitó hablar con un humano."
      );

      if (!sent) {
        return interaction.reply({
          content: "⚠️ No he podido avisar al fundador. Revisa la configuración de FOUNDER_USER_ID.",
          ephemeral: true
        });
      }

      return interaction.reply({
        content: "👤 He avisado al equipo para que atienda tu ticket.",
        ephemeral: false
      });
    } catch (error) {
      console.error(error);
      return interaction.reply({
        content: "⚠️ No he podido avisar al equipo en este momento.",
        ephemeral: true
      });
    }
  }

  if (interaction.customId === "ticket_close") {
    if (!interaction.memberPermissions.has(PermissionFlagsBits.ManageChannels)) {
      return interaction.reply({
        content: "❌ No tienes permisos para cerrar este ticket.",
        ephemeral: true
      });
    }

    await interaction.reply("🔒 Cerrando ticket...");
    sessions.delete(interaction.channel.id);
    setTimeout(() => interaction.channel.delete().catch(() => {}), 1500);
  }
});

async function escalateToFounder(channel, session, reason, aiResponse = "") {
  if (session.escalated) return true;

  const guildConfig = await getGuildConfig(channel.guild.id);
  if (!guildConfig.founderId) return false;

  const founder = await client.users.fetch(guildConfig.founderId);

  const summary = session.history
    .slice(-10)
    .map(x => `${x.role === "user" ? "Usuario" : "IA"}: ${x.content}`)
    .join("\n");

  await founder.send({
    content:
      `🚨 **Ticket requiere atención**\n\n` +
      `🎫 **Ticket:** ${channel}\n` +
      `👤 **Usuario:** <@${session.ownerId}>\n` +
      `📌 **Motivo:** ${reason}\n\n` +
      `🤖 **Respuesta exacta enviada al usuario:**\n${aiResponse || "(sin respuesta)"}\n\n` +
      `📝 **Conversación reciente:**\n${summary || "(sin mensajes)"}\n\n` +
      `🔗 ${channel.url}`
  });

  session.escalated = true;
  return true;
}
client.on("messageCreate", async message => {
  if (message.author.bot || !message.guild) return;
  if (message.channel.type !== ChannelType.GuildText) return;
  if (!message.channel.topic?.startsWith("ticket-owner:")) return;

  const guildConfig = await getGuildConfig(message.guild.id);
  if (guildConfig.staffRoleId && message.member.roles.cache.has(guildConfig.staffRoleId)) return;
  if (guildConfig.founderId && message.author.id === guildConfig.founderId) return;

  const session = sessions.get(message.channel.id) || {
    ownerId: message.author.id,
    history: [],
    escalated: false
  };
  sessions.set(message.channel.id, session);

  const mentionedAgent = message.mentions.has(client.user.id);
  const cleanContent = message.content
    .replace(new RegExp("<@!?"+client.user.id+">", "g"), "")
    .trim();

  // Mencionar al agente vuelve a activar la conversación del ticket.
  if (mentionedAgent) {
    session.escalated = false;

    if (!cleanContent) {
      session.history.push({
        role: "user",
        content: "[El usuario volvió a mencionar al agente para continuar la conversación.]"
      });

      await message.channel.send(
        "👋 Aquí estoy de nuevo. Cuéntame qué necesitas y seguimos con tu ticket."
      );
      return;
    }
  }

  session.history.push({ role: "user", content: cleanContent || message.content });

  if (session.escalated) return;

  try {
    const handledDirectly = await handleDirectRequest(message, session);
    if (handledDirectly) return;

    await message.channel.sendTyping();

    const result = await answerWithAI({
      history: session.history,
      channelName: message.channel.name,
      guildConfig
    });

    session.history.push({ role: "assistant", content: result.text });

    if (result.escalate || shouldEscalate(result.text)) {
      try {
        const sent = await escalateToFounder(
          message.channel,
          session,
          "La consulta requiere intervención humana.",
          result.text
        );

        if (sent) {
          await message.channel.send(
            result.text || "👤 Este caso requiere intervención humana. He avisado al equipo para que lo revise."
          );
        } else {
          await message.channel.send(
            "⚠️ " +
            (result.text || "Este caso requiere intervención humana.") +
            "\n\nNo he podido avisar al fundador. Revisa la configuración de FOUNDER_USER_ID."
          );
        }
      } catch (error) {
        console.error("Error escalando ticket:", error);
        await message.channel.send(
          "⚠️ Este caso requiere intervención humana, pero no he podido avisar al equipo en este momento."
        );
      }
      return;
    }
    await message.channel.send(result.text);
  } catch (error) {
    console.error(error);
    await message.channel.send(
      "⚠️ He tenido un problema procesando tu consulta. He avisado al equipo."
    );

    try {
      const founder = await client.users.fetch(guildConfig.founderId);
      await founder.send(
        `⚠️ Error del agente IA en ${message.channel.url}\n\n${error.message}`
      );
    } catch {}
  }
});

async function bootstrap() {
  try {
    await initDatabase();
  } catch (error) {
    console.error("❌ PostgreSQL no disponible:", error.message);
    process.exit(1);
  }

  startDashboard({ client, sessions });
  await client.login(config.token);
}

bootstrap();
