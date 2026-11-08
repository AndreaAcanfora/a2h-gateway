# a2h-gateway

[![CI](https://github.com/AndreaAcanfora/a2h-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/AndreaAcanfora/a2h-gateway/actions/workflows/ci.yml)

A self-hosted gateway for **[A2H](https://github.com/twilio-labs/Agent2Human)**,
the Agent-to-Human protocol: AI agents and scripts ask a person for approval
or information, the person answers from email, Telegram or a push
notification, and the agent gets a **signed answer with proof of who
decided**. A single Go binary with SQLite.

```console
$ a2h ask -to mailto:me@example.com -why "Rolls back if health checks fail." "Deploy v2.3 to production?"
Waiting for an answer from mailto:me@example.com (interaction 01a1bbcf-…)…
Approved (email_link.v1) at 2026-11-08T15:37:50Z.
$ echo $?
0
```

A2H was published by Twilio Labs in February 2026 with a specification, an
OpenAPI schema and a proof-of-concept demo. Its roadmap lists a reference
gateway and formal JSON Schemas as next steps. This project is an
**independent implementation** of both, not affiliated with Twilio.

## What it does

- **The whole agent-facing API** of A2H 1.0: discovery (`/.well-known/a2h`),
  `POST /v1/intent`, status, cancel, nonces, JWKS.
- **All intents:** AUTHORIZE (approve or decline), COLLECT (forms with text,
  choices, numbers and dates, validated), INFORM, RESULT, ESCALATE.
- **Channels:** email (SMTP), Telegram bot, push via [ntfy](https://ntfy.sh)
  (self-hosted or ntfy.sh), plus a console channel for development. Retries
  with the spec's backoff, and fallback channels.
- **Proof of decision:**
  - every RESPONSE is signed (ES256 detached JWS over JCS, keys in the JWKS);
  - requests with `assurance.level: HIGH` must be approved with a **passkey**
    (WebAuthn), with the challenge bound to the interaction as section 1.11.4
    requires.
- **Replay protection:**
  - idempotency on `message_id`;
  - timestamp window and single-use nonces;
  - single-use, unguessable links that expire with the interaction.
- **Webhooks** signed with HMAC (`X-A2H-Signature`), retried 10 s / 60 s /
  5 min, and polling as fallback.
- **JSON Schemas** for every A2H message, in [`schemas/`](schemas/).
- **MCP server** (`a2h mcp`): agents in Claude, Cursor and other MCP clients
  ask you for approval as a tool.
- **Conformance suite** to test any A2H gateway: `a2h conform`.

## Quick start

Download a binary for Linux, macOS, Windows or FreeBSD from the
[releases](https://github.com/AndreaAcanfora/a2h-gateway/releases), use the
Docker image `ghcr.io/andreaacanfora/a2h-gateway`, or install with Go:

```sh
go install github.com/AndreaAcanfora/a2h-gateway/cmd/a2h@latest

# Development: no authentication, links printed in the log.
A2H_BASE_URL=http://localhost:8080 A2H_DEV=1 a2h serve
```

In another terminal:

```sh
A2H_GATEWAY=http://localhost:8080 a2h ask -to console:me "Delete 3 unused files?"
```

The gateway logs a link (`url=http://localhost:8080/i/…`): open it,
approve, and `a2h ask` exits with 0.

### In production

```sh
docker run -d -p 8080:8080 -v a2h-data:/data \
  -e A2H_BASE_URL=https://a2h.example.com \
  -e A2H_API_KEYS="deploy-bot:$(openssl rand -hex 24)" \
  -e SMTP_HOST=smtp.example.com -e SMTP_USERNAME=a2h@example.com -e SMTP_PASSWORD=… \
  -e TELEGRAM_BOT_TOKEN=123456:ABC… \
  -e A2H_PUSH=1 \
  ghcr.io/andreaacanfora/a2h-gateway
```

Put it behind HTTPS: people open its links, and passkeys only work on a
secure origin.

**Telegram:** create a bot with [@BotFather](https://t.me/BotFather), then
send your bot any message so that it may write to you. Your chat ID is in
`https://api.telegram.org/bot<token>/getUpdates` (`message.chat.id`).
Messages get an action button when `A2H_BASE_URL` is a public host name;
with `localhost` the link is in the text, since Telegram refuses such
buttons.

| Variable | Meaning |
|---|---|
| `A2H_BASE_URL` | Public URL people open (required) |
| `A2H_LISTEN` | Listen address, default `:8080` |
| `A2H_DATA_DIR` | Database, signing key and link secret, default `./a2h-data` |
| `A2H_API_KEYS` | `name:key` pairs, comma-separated; agents send `X-A2H-API-Key` |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` | Email channel (STARTTLS or TLS) |
| `TELEGRAM_BOT_TOKEN` | Telegram channel; addresses are `tg:<chat_id>` (see below) |
| `A2H_PUSH`, `NTFY_TOKEN` | Push channel (ntfy); addresses are topic URLs |
| `A2H_CONSOLE` | Console channel (links in the log) |
| `A2H_DEV` | Development mode: no auth, `http://` webhooks, console. Never expose it. |

## Asking from an agent

Any HTTP client works:

```sh
curl -s https://a2h.example.com/v1/intent -H "X-A2H-API-Key: $KEY" -H 'content-type: application/json' -d '{
  "type": "AUTHORIZE",
  "message_id": "'$(uuidgen)'",
  "agent_id": "did:web:booking-agent.example.com",
  "principal_id": "usr_alice",
  "channel": { "type": "email", "address": "mailto:alice@example.com",
               "fallback": [{ "type": "push", "address": "https://ntfy.sh/alice-a2h-7f3k" }] },
  "render": { "title": "Book flight?", "body": "Book the non-refundable flight to Lisbon for 412 EUR?" },
  "explanation_bundle": { "why": "The fare expires in 30 minutes." },
  "ttl_sec": 1800,
  "callback": { "url": "https://agent.example.com/a2h/webhook", "secret": "whsec_…" }
}'
```

Then wait for the webhook, or poll `GET /v1/status/{interaction_id}` until
the state is `ANSWERED`, `EXPIRED`, `CANCELLED` or `FAILED`.

From Go, the `a2h` package does all of this and verifies the answer:

```go
c := a2h.NewClient("https://a2h.example.com", key)
sent, _ := c.Send(ctx, msg)
status, _ := c.Wait(ctx, sent.InteractionID, 2*time.Second)
resp, err := c.VerifyResponse(ctx, status.Response, msg.MessageID) // checks responds_to and the JWS
if err == nil && resp.Decision == a2h.Approve { /* go ahead */ }
```

## Use it from AI agents (MCP)

`a2h mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server: Claude Code, Claude Desktop, Cursor and other MCP clients get tools
to ask you before acting.

| Tool | What it does |
|---|---|
| `request_approval` | Ask you to approve or decline an action; returns the verified decision |
| `ask_human` | Ask you to fill in a short form (text, numbers, dates, choices, yes/no) |
| `notify_human` | Send you a message (progress, result, alert) |
| `check_request` | Follow up on a request that is still waiting |
| `cancel_request` | Withdraw a request that has not been answered |

Claude Code:

```sh
claude mcp add a2h \
  -e A2H_GATEWAY=https://a2h.example.com -e A2H_API_KEY=… -e A2H_TO=tg:123456789 \
  -- a2h mcp
```

Claude Desktop (`claude_desktop_config.json`), Cursor and others:

```json
{
  "mcpServers": {
    "a2h": {
      "command": "a2h",
      "args": ["mcp"],
      "env": { "A2H_GATEWAY": "https://a2h.example.com", "A2H_API_KEY": "…", "A2H_TO": "mailto:me@example.com" }
    }
  }
}
```

Then tell the agent when to ask, e.g. *"ask me with request_approval before
deleting anything or spending money"*.

- **The recipient is configuration.** The model can write the question but
  cannot choose whom it goes to, so an agent cannot message other people.
- **Answers are verified** against the gateway's signature before the tool
  reports a decision. An answer that fails verification is reported as a
  failure, never as an approval.
- **Long waits:** a tool call waits up to 10 minutes (`-max-wait`) and
  sends progress notifications meanwhile. If the person has not answered by
  then, the tool says so and the agent continues with `check_request`.
- **High stakes:** `require_passkey: true` makes the approval need a passkey.

## Passkeys for high-stakes approvals

Requests with `"assurance": {"level": "HIGH"}` (or `required_factors`
containing `passkey.webauthn.v1`) cannot be approved with a click: the
person must confirm with a passkey (Face ID, Touch ID, Windows Hello, a
security key). Only the operator can register passkeys, from the server:

```sh
a2h enroll -principal usr_alice
# Send this link to usr_alice. It works once and expires in 24h0m0s:
# https://a2h.example.com/enroll/…
```

The RESPONSE then carries the WebAuthn assertion, the challenge nonce and the
public key, so an agent can verify the person's signature itself.

## Conformance

```sh
a2h conform -gateway https://gateway.example.com -key $KEY -to mailto:a2h-test@example.com
```

```
PASS  MUST   §1.4      discovery document
PASS  MUST   §1.3      RESPONSE type from an agent is rejected
PASS  MUST   §1.5      unsupported profile is rejected
PASS  MUST   §1.10.2   duplicate message_id returns the original interaction
PASS  MUST   §1.7      cancel a waiting interaction
…
conforming to the agent-facing API of A2H 1.0
```

The suite sends real intents to the address you give, then cancels them.

## Where the spec was unclear

A2H 1.0 leaves some details open or describes them two ways. The choices
made here are listed in [docs/implementation-notes.md](docs/implementation-notes.md),
as feedback for the next version of the spec.

## Development

```sh
go test -race ./...                        # unit and integration tests
go build -o e2e/a2h ./cmd/a2h && (cd e2e && npm install && npm test)   # passkeys in Chromium
```

## License

MIT. A2H is © Twilio Labs, under the MIT License.
