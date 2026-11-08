// End-to-end test in a real browser: a person enrolls a passkey, then
// approves a HIGH-assurance AUTHORIZE with it. Chromium's virtual
// authenticator stands in for the person's device.
//
//   go build -o e2e/a2h ./cmd/a2h && cd e2e && npm install && npm test
//
// CHROMIUM_PATH lets the test use a browser already on the machine.
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { chromium } from 'playwright'

const bin = new URL('./a2h', import.meta.url).pathname
const port = 20000 + Math.floor(Math.random() * 10000)
const base = `http://localhost:${port}`
const key = 'e2e-key-0123456789abcdef'
const env = {
  ...process.env,
  A2H_BASE_URL: base,
  A2H_LISTEN: `127.0.0.1:${port}`,
  A2H_DATA_DIR: mkdtempSync(join(tmpdir(), 'a2h-e2e-')),
  A2H_API_KEYS: `e2e:${key}`,
  A2H_PUSH: '1',
}

// A stand-in for an ntfy server: records the links pushed to the person.
const pushed = []
const ntfy = createServer((req, res) => {
  pushed.push({ topic: req.url, click: req.headers.click })
  req.resume()
  res.end('{}')
})
await new Promise((r) => ntfy.listen(0, '127.0.0.1', r))
const topic = `http://127.0.0.1:${ntfy.address().port}/alice-e2e`

const gateway = spawn(bin, ['serve'], { env, stdio: ['ignore', 'ignore', 'pipe'] })
let log = ''
gateway.stderr.on('data', (d) => (log += d))
for (let i = 0; i < 50 && !log.includes('listening'); i++) await new Promise((r) => setTimeout(r, 100))

const api = async (method, path, body) => {
  const res = await fetch(base + path, { method, headers: { 'x-a2h-api-key': key, 'content-type': 'application/json' }, body: body && JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
const authorize = async (title) => {
  const messageId = crypto.randomUUID()
  const r = await api('POST', '/v1/intent', {
    type: 'AUTHORIZE', message_id: messageId, agent_id: 'did:web:e2e.invalid', principal_id: 'usr_alice',
    channel: { type: 'push', address: topic }, render: { title, body: `${title}: transfer 500 EUR to ACME Ltd.` },
    assurance: { level: 'HIGH', required_factors: ['passkey.webauthn.v1'] }, ttl_sec: 300,
  })
  assert.equal(r.status, 200, JSON.stringify(r.body))
  const id = r.body.interaction_id
  for (let i = 0; i < 50; i++) {
    const s = await api('GET', `/v1/status/${id}`)
    if (s.body.state === 'WAITING_INPUT') break
    await new Promise((r) => setTimeout(r, 100))
  }
  const link = pushed.findLast((p) => p.topic === '/alice-e2e').click
  return { id, messageId, link }
}

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {})
try {
  const context = await browser.newContext()
  const page = await context.newPage()
  const cdp = await context.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  })

  // 1. The operator creates an enrollment link; the person creates a passkey.
  const enrollLink = execFileSync(bin, ['enroll', '-principal', 'usr_alice'], { env, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim()
  await page.goto(enrollLink)
  await page.click('#enroll')
  await page.waitForFunction(() => document.getElementById('status').textContent.includes('Passkey created'))
  console.log('ok - passkey enrolled')
  await page.goto(enrollLink)
  assert.match(await page.textContent('main'), /expired or already used/)
  console.log('ok - enrollment link is single-use')

  // 2. A HIGH-assurance request: plain approval is refused, the passkey works.
  const a = await authorize('Payment A')
  const verifyBodies = []
  page.on('request', (r) => { if (r.url().endsWith('/passkey/verify')) verifyBodies.push(r.postData()) })
  await page.goto(a.link)
  assert.match(await page.textContent('main'), /Payment A: transfer 500 EUR/)
  await page.click('#approve-passkey')
  await page.waitForFunction(() => document.body.textContent.includes('You approved this request'))
  const s = await api('GET', `/v1/status/${a.id}`)
  assert.equal(s.body.state, 'ANSWERED')
  const resp = s.body.response
  assert.equal(resp.decision, 'APPROVE')
  assert.equal(resp.responds_to, a.messageId)
  assert.equal(resp.evidence.factor, 'passkey.webauthn.v1')
  assert.match(resp.signature, /^[\w-]+\.\.[\w-]+$/)
  console.log('ok - approved with a passkey, signed RESPONSE with passkey evidence')

  // 3. The WebAuthn challenge is bound to this interaction (spec 1.11.4).
  const clientData = JSON.parse(Buffer.from(resp.evidence.proof.clientDataJSON, 'base64url'))
  const expected = createHash('sha256').update(a.id + resp.evidence.proof.challenge_nonce).digest('base64url')
  assert.equal(clientData.challenge, expected)
  assert.equal(clientData.type, 'webauthn.get')
  assert.equal(clientData.origin, base)
  console.log('ok - challenge = base64url(sha256(interaction_id + nonce))')

  // 4. That assertion cannot approve another request.
  const b = await authorize('Payment B')
  const tokenB = new URL(b.link).pathname
  const opts = await fetch(base + tokenB + '/passkey/options', { method: 'POST' })
  assert.equal(opts.status, 200)
  const replay = await fetch(base + tokenB + '/passkey/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: verifyBodies[0] })
  assert.equal(replay.status, 401)
  assert.equal((await api('GET', `/v1/status/${b.id}`)).body.state, 'WAITING_INPUT')
  console.log('ok - a passkey assertion from one request is rejected for another')

  // 5. Plain link approval of a HIGH request is refused.
  const form = await fetch(b.link, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'decision=APPROVE' })
  assert.equal(form.status, 422)
  assert.equal((await api('GET', `/v1/status/${b.id}`)).body.state, 'WAITING_INPUT')
  console.log('ok - HIGH assurance cannot be approved without the passkey')
} finally {
  await browser.close()
  gateway.kill()
  ntfy.close()
}
