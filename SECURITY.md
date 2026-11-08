# Security

a2h-gateway decides whether an AI agent may act on a person's behalf, so
security reports are welcome and handled first.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting:
[Report a vulnerability](https://github.com/AndreaAcanfora/a2h-gateway/security/advisories/new)
(Security tab → Report a vulnerability).

Include the version (`a2h version`), what an attacker can do, and how to
reproduce it. You can expect an acknowledgement within a few days. Fixes are
released as a new version, with credit to the reporter unless they prefer
otherwise.

## Supported versions

The project is at 0.x: only the latest release receives security fixes.

## What the gateway protects

- **Agents are authenticated** by API key (`X-A2H-API-Key`), compared in
  constant time. An agent can read and cancel only its own interactions.
- **Links are capabilities.** Each link holds 256 bits derived with HMAC
  from a per-gateway secret; only its hash is stored. A link works once, and
  stops working when the interaction expires or is cancelled.
- **Answers come from the gateway's own pages.** Form posts must be
  same-origin (`Origin` and `Sec-Fetch-Site`); the pages forbid framing and
  send a strict Content Security Policy.
- **Answers are signed.** Every RESPONSE and ERROR message carries an ES256
  JWS over its JCS form; agents verify it against the published JWKS
  (`a2h.Client.VerifyResponse` does this, and so does the MCP server).
- **Passkeys for high stakes.** With `assurance.level: HIGH`, approval
  requires a WebAuthn assertion whose challenge is bound to the interaction,
  so an assertion cannot be replayed on another request. Only the operator
  can create enrollment links (`a2h enroll`), never an agent.
- **Replay protection:** idempotent `message_id` per caller, ±5 minute
  `created_at` window, single-use nonces.
- **Webhooks are signed** with HMAC-SHA256 and a timestamp
  (`X-A2H-Signature`); callbacks must be HTTPS.
- **The MCP server** takes the recipient from configuration only, so a
  model cannot contact other people.

## What it does not protect against

- **A compromised channel.** Whoever can read the person's email, Telegram
  chat or ntfy topic can open the link and approve. Use passkeys
  (`assurance.level: HIGH`) for actions where that matters, and use a
  secret, hard-to-guess ntfy topic.
- **Link evidence is the gateway's word.** `email_link.v1` and `link.v1`
  attest that the link was opened and answered; they carry no signature
  from the person. Only `passkey.webauthn.v1` does.
- **Agent signatures on intents are not verified** (the A2H spec defines no
  way to find an agent's keys); agents are trusted by API key.
- **A compromised host.** The data directory holds the signing key, the
  link secret, webhook secrets and pending requests; the environment holds
  the API keys and channel credentials.

## Running it safely

- Serve it over **HTTPS** only (passkeys require a secure origin), behind a
  reverse proxy that forwards the `Origin` and `Sec-Fetch-*` headers.
- **Never set `A2H_DEV=1`** on a reachable host: it disables authentication.
- Use API keys of at least 24 random bytes, one per agent, and rotate them by
  changing `A2H_API_KEYS`.
- Protect the data directory (`A2H_DATA_DIR`, created with mode 0700) and
  back it up: losing `signing-key.pem` invalidates verification of past
  answers, and losing `link-secret` invalidates pending links.
- Pass secrets (SMTP password, Telegram token, API keys) as environment
  variables or Docker secrets, not in files committed anywhere.
