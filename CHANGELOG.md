# Changelog

## v0.2.1 — 2026-11-08

- Listed in the official MCP Registry as `io.github.AndreaAcanfora/a2h-gateway` (`server.json`, ownership label on the image, published by the release workflow).
- Docker image also tagged with the bare version (`0.2.1`).

## v0.2.0 — 2026-11-08

- MCP server (`a2h mcp`): tools `request_approval`, `ask_human`, `notify_human`, `check_request`, `cancel_request`.
- Telegram: messages are delivered when the gateway URL is not public (link in the text).
- `go install` builds report their module version.

## v0.1.0 — 2026-11-08

- Fixed: approving from the form in a real browser returned 403 (Origin: null).
- Release binaries and a multi-arch Docker image on ghcr.io.

- A2H 1.0 gateway: discovery, intents (INFORM, COLLECT, AUTHORIZE, ESCALATE, RESULT), status, cancel, nonces, JWKS.
- Channels: email (SMTP), Telegram, push (ntfy), console; retries and fallback channels.
- Signed RESPONSE messages (ES256 detached JWS over JCS), passkey approvals bound to the interaction, link evidence.
- Signed webhooks with retries; ERROR messages for expired and failed interactions.
- JSON Schemas for all A2H 1.0 messages.
- `a2h` command: `serve`, `enroll`, `ask`, `notify`, `status`, `conform`.
