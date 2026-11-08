# Changelog

## Unreleased

- A2H 1.0 gateway: discovery, intents (INFORM, COLLECT, AUTHORIZE, ESCALATE, RESULT), status, cancel, nonces, JWKS.
- Channels: email (SMTP), Telegram, push (ntfy), console; retries and fallback channels.
- Signed RESPONSE messages (ES256 detached JWS over JCS), passkey approvals bound to the interaction, link evidence.
- Signed webhooks with retries; ERROR messages for expired and failed interactions.
- JSON Schemas for all A2H 1.0 messages.
- `a2h` command: `serve`, `enroll`, `ask`, `notify`, `status`, `conform`.
