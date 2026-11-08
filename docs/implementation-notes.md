# Implementation notes

How this gateway reads the parts of the A2H v1.0 specification
([a2h_framework.md](https://github.com/twilio-labs/Agent2Human/blob/main/a2h_framework.md)
and [a2h-protocol.yaml](https://github.com/twilio-labs/Agent2Human/blob/main/a2h-protocol.yaml))
that are ambiguous, contradictory or left open. Each note says what the spec
says, what this gateway does and why. They are offered as feedback for a
future version of the spec.

## Messages and states

**1. States of intents that expect no answer.** The state machine (1.6)
describes interactions that wait for input. INFORM, RESULT and ESCALATE never
reach WAITING_INPUT. *Here:* they stop at SENT, which is terminal for them.
`a2h.Terminal(state, type)` encodes this.

**2. RESPONSE to COLLECT.** `decision` is APPROVE or DECLINE, which fits
AUTHORIZE. For a COLLECT, the person sends data. *Here:* a submitted form
gives a RESPONSE with `data` and no `decision`; "Decline to answer" gives
`decision: DECLINE` and no data.

**3. Follow-ups in an interaction.** RESULT carries `responds_to` and shares
the `interaction_id` of the AUTHORIZE it reports on, but
`/v1/status/{interactionId}` returns one state. *Here:* an intent that
reuses an existing `interaction_id` is accepted only if it expects no answer
(RESULT, INFORM, ESCALATE). It is delivered as a follow-up, and the status
endpoint keeps returning the original intent. Asking again (AUTHORIZE or
COLLECT) in the same interaction is `ERR.CONFLICT`.

**4. HTTP status of POST /v1/intent.** The OpenAPI document says 200; the
demo answers 202. *Here:* 200.

## Cancellation

**5. What can be cancelled.** Section 1.7 says only WAITING_INPUT can be
cancelled; the OpenAPI document says "a pending or active interaction".
*Here:* AUTHORIZE and COLLECT can be cancelled in PENDING, SENT and
WAITING_INPUT; INFORM, RESULT and ESCALATE only before delivery.

**6. Response body.** Section 1.7 shows `success`, `message` and `state`;
the OpenAPI document lists `success` and `message`. *Here:* all three.

## Errors

**7. Two error shapes.** The ERROR message has `error: {code, message}`;
the HTTP ErrorResponse has `error: "ERR.X"` and `message`. *Here:* HTTP
errors use ErrorResponse, webhooks use the ERROR message.

**8. Codes outside the enumeration.** 401 and 404 responses need a code, and
the ErrorCode enumeration has none for them. *Here:* `ERR.UNAUTHORIZED` and
`ERR.NOT_FOUND`. The JSON Schema in `schemas/` accepts any `ERR.` code.

**9. Webhooks when nobody answers.** Section 1.12.3 sends a webhook when the
human responds. An agent that relies on webhooks would wait forever for an
interaction that expires or fails. *Here:* the gateway also sends a signed
ERROR message (`ERR.EXPIRED`, `ERR.DELIVERY_FAILED`) to the callback.

## Webhooks

**10. X-A2H-Delivery-ID.** Section 1.12.3 calls it "unique ID for this
delivery attempt", and 1.12.7 uses it to deduplicate deliveries. A new ID per
attempt makes deduplication impossible. *Here:* one ID per event, repeated on
every retry of that event.

## Evidence and signatures

**11. JWS details.** "Detached JWS over JCS canonical payload" leaves open
the algorithm and the detached form. *Here:* ES256, compact serialization
with an empty payload part (RFC 7515 appendix F), the payload being the JCS
form (RFC 8785) of the message without its `signature` member, and `kid`
being the RFC 7638 thumbprint published in the JWKS.

**12. Evidence for link approvals.** Many people approve by opening a link
delivered on a channel. No factor describes this. *Here:* `email_link.v1`
(listed in the discovery example) for email, `link.v1` for other channels.
The proof is the gateway's attestation (`verified_at`, `delivery_channel`,
`channel_type`), like OTP evidence (1.11.5).

**13. Passkey evidence.** Section 1.11.4 binds the challenge to
`sha256(interaction_id + nonce)`, but the RESPONSE does not carry the nonce,
so an agent cannot check the binding. *Here:* the proof also contains
`challenge_nonce` and the credential's `publicKey` (COSE), so that an agent
can recompute the challenge and verify the assertion without trusting the
gateway.

**14. Agent signatures.** Section 1.1 asks for one JWS per message, including
intents, but defines no way to find an agent's keys. *Here:* the `signature`
of intents is accepted but not verified; agents are authenticated by API
key (1.8.3).

## Replay protection

**15. Idempotency scope.** *Here:* `message_id` is unique per authenticated
caller, so two agents cannot collide or probe each other's IDs.

**16. Missing created_at.** Section 1.10.3 validates `created_at`, which the
OpenAPI document does not require. *Here:* checked when present, within
±5 minutes.

## Channels

**17. Address schemes.** The spec names `tel:` and `mailto:`. *Here:* email
uses `mailto:`, Telegram uses `tg:<chat_id>`, push (ntfy) uses the topic URL
`https://…`, and the development console uses `console:<name>`.

**18. Passkeys need a domain.** WebAuthn binds credentials to a domain, so
the gateway refuses a base URL with an IP address (use `localhost` for local
development).
