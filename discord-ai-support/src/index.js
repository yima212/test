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
      history: []
    });

    const closeRow = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("ticket_close")
        .setLabel("Cerrar ticket")
        .setEmoji("🔒")
        .setStyle(ButtonStyle.Danger)
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

client.on("messageCreate", async message => {
  if (message.author.bot || !message.guild) return;
  if (message.channel.type !== ChannelType.GuildText) return;
  if (!message.channel.topic?.startsWith("ticket-owner:")) return;

  if (config.staffRoleId && message.member.roles.cache.has(config.staffRoleId)) return;
  if (message.author.id === config.founderId) return;

  const session = sessions.get(message.channel.id) || {
    ownerId: message.author.id,
    history: []
  };
  sessions.set(message.channel.id, session);

  session.history.push({ role: "user", content: message.content });

  try {
    await message.channel.sendTyping();

    const result = await answerWithAI({
      history: session.history,
      channelName: message.channel.name
    });

    session.history.push({ role: "assistant", content: result.text });

    if (result.escalate || shouldEscalate(result.text)) {
      const founder = await client.users.fetch(config.founderId);

      const summary = session.history
        .slice(-8)
        .map(x => `${x.role === "user" ? "Usuario" : "IA"}: ${x.content}`)
        .join("\n");

      await founder.send({
        content:
          `🚨 **Ticket requiere atención**\n\n` +
          `🎫 **Ticket:** ${message.channel}\n` +
          `👤 **Usuario:** <@${session.ownerId}>\n\n` +
          `📝 **Conversación reciente:**\n${summary}\n\n` +
          `🔗 ${message.channel.url}`
      });

      await message.channel.send(
        "👤 No tengo información suficiente para resolver esto con seguridad. He avisado al equipo para que revise tu ticket."
      );
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
