const {
  REST,
  Routes,
  SlashCommandBuilder,
  PermissionFlagsBits
} = require("discord.js");

const config = require("./config");

if (!config.token || !config.clientId) {
  throw new Error("Faltan DISCORD_TOKEN o CLIENT_ID en .env");
}

const commands = [
  new SlashCommandBuilder()
    .setName("panel")
    .setDescription("Publica el panel para abrir tickets")
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild.bitfield)
    .toJSON()
];

const rest = new REST({ version: "10" }).setToken(config.token);

(async () => {
  try {
    console.log("Registrando comandos slash...");
    await rest.put(
      Routes.applicationCommands(config.clientId),
      { body: commands }
    );
    console.log("Comando /panel global registrado correctamente.");
  } catch (error) {
    console.error("Error registrando comandos:", error);
    process.exitCode = 1;
  }
})();
