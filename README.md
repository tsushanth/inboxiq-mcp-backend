# inboxiq-mcp-backend

Public relay + OAuth 2.0 authorization server so InboxIQ's on-device MCP
server can be added as a real Claude Connector (claude.ai / Claude Desktop),
synced across devices — not just usable from Claude Code CLI on the same
Wi-Fi (see `../InboxIQ/docs/mcp-server.md` for that simpler, local-only path,
which still works independently of this).

## Why a separate service from the phone's own MCP server

The phone's embedded server (`InboxIQ/app/.../mcp/McpServer.kt`) is
intentionally LAN-only — that's what keeps InboxIQ's "message content never
leaves the device" story true for the Claude Code CLI flow. This backend is
a deliberate, explicit exception to that for people who want Connector-level
convenience (any device, no same-Wi-Fi requirement, account-synced) — message
content passes through this backend in transit to relay live tool calls. It
is never stored: only OAuth tokens, phone-number links, and pairing metadata
are persisted (see `db.js`).

## Architecture

```
Claude (claude.ai / Desktop)
   │  OAuth (dynamic client registration, PKCE)
   ▼
inboxiq-mcp-backend  (this repo, public, mcp.kreativekoala.llc)
   │  WebSocket (long-lived, phone-initiated)
   ▼
InboxIQ app on the user's phone
```

- `/authorize` — phone number entry → Twilio SMS OTP → proves the Claude
  account maps to this specific phone, issues an auth code.
- `/token` — exchanges the auth code (PKCE-verified) for an access + refresh
  token.
- `/phone-ws` — the InboxIQ app holds a persistent WebSocket connection here,
  authenticated with its own relay token (separate from anything Claude
  sees).
- `/mcp` — what Claude actually calls per-request; resolves the OAuth access
  token to a phone number, relays the JSON-RPC body to that phone's live
  WebSocket connection, and returns whatever it responds with.

## Required secrets (set via `flyctl secrets set`, never committed)

- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE_NUMBER` — reused
  from the existing `ai-notetaker-backend` Twilio account.

## Status

Scaffolded, not yet deployed or end-to-end tested. Still needed:
- [ ] The phone-side WebSocket client (new Android code) that calls
      `/phone/link` and holds the `/phone-ws` connection open
- [ ] Real deploy + DNS (`mcp.kreativekoala.llc` → this Fly app)
- [ ] End-to-end test: add as a Connector in claude.ai, confirm it relays a
      real tool call to a real phone
