# The app channel: answering from a phone

The `app` channel delivers requests to a phone app paired with the gateway,
such as [nod](https://github.com/AndreaAcanfora/nod). Answers are signed by a
P-256 key created on the phone, and the signed answer travels inside the
RESPONSE as evidence, so an agent can check it without taking the gateway's
word for it.

This is an extension of this gateway, not part of the A2H 1.0 specification.
Any app can implement it: this page is the whole contract.

## For operators

```sh
a2h pair -principal alice          # prints a QR code and a single-use link (1 hour)
a2h devices                        # lists paired phones
a2h devices -revoke dev_…          # unpairs one
```

Agents then use the address `app:alice`:

```json
{ "channel": { "type": "app", "address": "app:alice",
               "fallback": [ { "type": "email", "address": "mailto:alice@example.com" } ] } }
```

If no phone is paired for `alice`, the delivery fails at once and the gateway
moves to the fallback channel. A request delivered by any channel also shows up
in the app, so a phone can answer requests that arrived by email or Telegram.

Requests with `assurance.level: HIGH` (or `required_factors` containing
`passkey.webauthn.v1`) still need a passkey: the app can decline them, and
opens the web page to approve.

## For app developers

All requests and answers are JSON. The app authenticates with the device token
it gets when pairing: `Authorization: Bearer <device_token>`.

### Pairing

The pairing link is `<base_url>/pair/<pairing_token>`. The app takes the base
URL and the token from it, creates a P-256 key pair, and sends:

```http
POST /v1/device/pair
{
  "pairing_token": "…",
  "name": "Pixel 9",
  "public_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "push_url": "https://ntfy.sh/upAbC…?up=1"      // optional
}
```

```json
{ "device_id": "dev_…", "device_token": "…", "principal_id": "alice",
  "gateway": { "base_url": "https://a2h.example.com", "jwks_uri": "https://a2h.example.com/.well-known/jwks.json" } }
```

The link works once. `410` means it is unknown, expired or used.

### Push

`push_url` is a [UnifiedPush](https://unifiedpush.org) endpoint (for example an
ntfy topic). For each request the gateway POSTs:

```json
{ "a2h": "interaction", "interaction_id": "…", "type": "AUTHORIZE" }
```

The push carries no content: the app fetches the request from the gateway, so
the push service never sees what the agent asked. Without a `push_url` the app
sees new requests when it refreshes. Change it with
`PATCH /v1/device {"push_url": "…"}` (and the name with `{"name": "…"}`).

### Inbox

```http
GET /v1/device/inbox
```

```json
{ "principal_id": "alice", "server_time": "2026-11-09T10:00:00Z", "items": [
  { "interaction_id": "…", "type": "AUTHORIZE", "state": "WAITING_INPUT", "agent_id": "claude-code",
    "title": "Push to main?", "body": "git push --force origin main", "why": "The rebase rewrote history.",
    "created_at": "…", "expires_at": "…", "web_url": "https://a2h.example.com/i/…",
    "required_factor": "passkey.webauthn.v1" }
] }
```

Requests waiting for an answer come first, then everything of the last seven
days with its outcome (`decision`, `decided_at`, `factor`, `data`, `error`).
COLLECT items carry the `components` of the form. `required_factor` is set
when the app cannot approve: open `web_url` instead.

### Answering

The app signs a compact JWS (RFC 7515) with ES256:

- header: `{"alg": "ES256", "typ": "a2h-device-answer+jws", "kid": "<RFC 7638 thumbprint of the key>"}`
- payload:

```json
{ "interaction_id": "…", "decision": "APPROVE", "device_id": "dev_…", "iat": 1794218400 }
```

`decision` is `APPROVE` or `DECLINE` for AUTHORIZE, `SUBMIT` for COLLECT (with
the answers in `data`: strings, numbers, booleans, or lists of strings for
MULTISELECT). `iat` must be within 5 minutes of the gateway's clock.

```http
POST /v1/device/answer
{ "jws": "eyJhbGciOiJFUzI1NiIs…" }
```

| Status | `error` | Meaning |
|---|---|---|
| 200 | | Recorded; `item` is the updated request |
| 401 | `bad_signature`, `unpaired` | Wrong key, or the device was unpaired |
| 403 | `passkey_required` | Approve in the browser (`web_url`) |
| 410 | `closed` | Already answered, expired or cancelled; `item` says how |
| 422 | `invalid_data` | Form errors in `problems`, by field name |

### Evidence

The RESPONSE that the agent receives (signed by the gateway as usual) has:

```json
"evidence": { "factor": "device_key.es256.v1", "proof": {
  "jws": "…", "public_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "…" },
  "device_id": "dev_…", "device_name": "Pixel 9", "verified_at": "…" } }
```

Verify the JWS with `public_key` and check that its `interaction_id` is yours
(`gateway.VerifyDeviceEvidence` does both). Pin the phone's key on first use,
or compare it with a key you trust, to know it is the person's phone and not a
key the gateway made up.

### Unpairing

`DELETE /v1/device` unpairs the phone. Afterwards every call answers `401`
with `"error": "unpaired"`.

## Security notes

- The pairing link is a bearer secret: whoever opens it first pairs a phone in
  that person's name. Send it over a channel you trust, and keep its TTL short.
- The device token only reads the person's requests; answers also need the
  signature of the phone's key. A leaked token alone cannot approve anything.
- The gateway POSTs to the `push_url` that a paired phone gives it. Only
  `https` URLs are accepted (plain `http` only with `A2H_DEV=1`).
