# Discord AI Support

Bot de Discord con:
- Panel para abrir tickets
- Creación automática de canales privados
- Agente IA
- Memoria de conversación por ticket
- Escalado al fundador por DM
- Cierre de tickets
- Configuración mediante .env

## Instalación

```bash
npm install
```

Copia .env.example como .env y completa las variables.

No publiques .env ni el token de Discord.

## Ejecutar

```bash
npm start
```

## Permisos recomendados

- View Channels
- Send Messages
- Read Message History
- Manage Channels
- Embed Links

Activa también el intent Message Content en Discord Developer Portal.

## Próximas mejoras

- Registro automático de slash commands
- /setup, /panel y /close
- Base de conocimiento editable
- Transcripciones
- Botón "Hablar con humano"
- Persistencia con SQLite/PostgreSQL
- Rate limiting y anti-spam
- Dashboard web
