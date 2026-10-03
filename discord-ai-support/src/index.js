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

    if (config.staffRoleId) {
      permissionOverwrites.push({
        id: config.staffRoleId,
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
  if (!config.founderId) return false;

  const founder = await client.users.fetch(config.founderId);

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

  if (config.staffRoleId && message.member.roles.cache.has(config.staffRoleId)) return;
  if (message.author.id === config.founderId) return;

  const session = sessions.get(message.channel.id) || {
    ownerId: message.author.id,
    history: [],
    escalated: false
  };
  sessions.set(message.channel.id, session);

  session.history.push({ role: "user", content: message.content });

  if (session.escalated) return;

  try {
    await message.channel.sendTyping();

    const result = await answerWithAI({
      history: session.history,
      channelName: message.channel.name
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
      const founder = await client.users.fetch(config.founderId);
      await founder.send(
        `⚠️ Error del agente IA en ${message.channel.url}\n\n${error.message}`
      );
    } catch {}
  }
});

client.login(config.token);
