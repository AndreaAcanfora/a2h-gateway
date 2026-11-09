package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/AndreaAcanfora/a2h-gateway/jws"
)

// phone plays the app: it holds a key and talks to the device API.
type phone struct {
	e     *env
	key   *ecdsa.PrivateKey
	id    string
	token string
}

func (p *phone) jwk() jws.JWK {
	b, _ := p.key.PublicKey.Bytes()
	enc := base64.RawURLEncoding.EncodeToString
	return jws.JWK{Kty: "EC", Crv: "P-256", X: enc(b[1:33]), Y: enc(b[33:65])}
}

func (p *phone) do(method, path string, body any) (int, map[string]any) {
	p.e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, p.e.g.cfg.BaseURL+path, r)
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) pairPhone(principal, pushURL string) *phone {
	e.t.Helper()
	link, err := e.g.CreatePairing(context.Background(), principal, time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &phone{e: e, key: k}
	token := link[strings.LastIndex(link, "/")+1:]
	code, out := p.do("POST", "/v1/device/pair", map[string]any{"pairing_token": token, "name": "Pixel", "public_key": p.jwk(), "push_url": pushURL})
	if code != 200 {
		e.t.Fatalf("pair: %d %v", code, out)
	}
	p.id, p.token = out["device_id"].(string), out["device_token"].(string)
	if out["principal_id"] != principal {
		e.t.Fatalf("pair: principal %v", out["principal_id"])
	}
	return p
}

// sign returns the compact JWS an app sends to answer.
func (p *phone) sign(a DeviceAnswer, typ string) string {
	enc := base64.RawURLEncoding.EncodeToString
	if a.DeviceID == "" {
		a.DeviceID = p.id
	}
	if a.IssuedAt == 0 {
		a.IssuedAt = p.e.clock.Now().Unix()
	}
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": typ, "kid": jws.Thumbprint(&p.key.PublicKey)})
	pl, _ := json.Marshal(a)
	input := enc(h) + "." + enc(pl)
	d := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, p.key, d[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc(sig)
}

func (p *phone) answer(a DeviceAnswer) (int, map[string]any) {
	return p.do("POST", "/v1/device/answer", map[string]string{"jws": p.sign(a, DeviceAnswerType)})
}

func (p *phone) inbox() []map[string]any {
	p.e.t.Helper()
	code, out := p.do("GET", "/v1/device/inbox", nil)
	if code != 200 {
		p.e.t.Fatalf("inbox: %d %v", code, out)
	}
	var items []map[string]any
	for _, it := range out["items"].([]any) {
		items = append(items, it.(map[string]any))
	}
	return items
}

func toApp(m *a2h.Message) { m.Channel = &a2h.Channel{Type: "app", Address: "app:usr_alice"} }

func TestAppApprove(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	var pushes []map[string]string
	pushSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		pushes = append(pushes, body)
		mu.Unlock()
	}))
	defer pushSrv.Close()
	p := e.pairPhone("usr_alice", pushSrv.URL+"/up123")

	r := e.send(e.intent(toApp))
	e.tick()
	if s := e.status(r.InteractionID); s.State != a2h.StateWaitingInput || s.ChannelID != "app" {
		t.Fatalf("status %+v", s)
	}
	mu.Lock()
	if len(pushes) != 1 || pushes[0]["interaction_id"] != r.InteractionID || strings.Contains(pushes[0]["a2h"], "Delete") {
		t.Fatalf("pushes %v", pushes)
	}
	mu.Unlock()

	items := p.inbox()
	if len(items) != 1 || items[0]["interaction_id"] != r.InteractionID || items[0]["title"] != "Delete files?" || items[0]["why"] != "This is irreversible." || items[0]["web_url"] == "" {
		t.Fatalf("inbox %v", items)
	}

	code, out := p.answer(DeviceAnswer{InteractionID: r.InteractionID, Decision: a2h.Approve})
	if code != 200 || out["item"].(map[string]any)["decision"] != a2h.Approve {
		t.Fatalf("answer: %d %v", code, out)
	}
	s := e.status(r.InteractionID)
	var resp a2h.ResponseMessage
	json.Unmarshal(s.Response, &resp)
	if s.State != a2h.StateAnswered || resp.Decision != a2h.Approve || resp.Evidence.Factor != a2h.FactorDeviceKey {
		t.Fatalf("status %+v response %+v", s, resp)
	}
	if err := jws.Verify(s.Response, jws.JWKS{Keys: []jws.JWK{e.g.Key().PublicJWK()}}); err != nil {
		t.Fatalf("gateway signature: %v", err)
	}
	a, err := VerifyDeviceEvidence(resp.Evidence, r.InteractionID)
	if err != nil || a.Decision != a2h.Approve || a.DeviceID != p.id {
		t.Fatalf("device evidence: %v %+v", err, a)
	}
	if _, err := VerifyDeviceEvidence(resp.Evidence, "other"); err == nil {
		t.Fatal("evidence verified for another interaction")
	}

	// Answers are single-use.
	if code, out := p.answer(DeviceAnswer{InteractionID: r.InteractionID, Decision: a2h.Decline}); code != http.StatusGone {
		t.Fatalf("second answer: %d %v", code, out)
	}
	if items := p.inbox(); items[0]["state"] != a2h.StateAnswered || items[0]["factor"] != a2h.FactorDeviceKey || items[0]["web_url"] != nil {
		t.Fatalf("inbox after %v", items)
	}
}

func TestAppRejectsForgedAnswers(t *testing.T) {
	e := newEnv(t)
	p := e.pairPhone("usr_alice", "")
	r := e.send(e.intent(toApp))
	e.tick()

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forger := &phone{e: e, key: other, id: p.id, token: p.token}
	if code, _ := forger.answer(DeviceAnswer{InteractionID: r.InteractionID, Decision: a2h.Approve}); code != http.StatusUnauthorized {
		t.Fatalf("answer signed by another key: %d", code)
	}
	if code, _ := p.do("POST", "/v1/device/answer", map[string]string{"jws": p.sign(DeviceAnswer{InteractionID: r.InteractionID, Decision: a2h.Approve}, "JWT")}); code != http.StatusBadRequest {
		t.Fatalf("wrong typ: %d", code)
	}
	if code, _ := p.answer(DeviceAnswer{InteractionID: r.InteractionID, Decision: a2h.Approve, IssuedAt: e.clock.Now().Add(-time.Hour).Unix()}); code != http.StatusBadRequest {
		t.Fatalf("stale answer: %d", code)
	}
	if code, _ := p.answer(DeviceAnswer{InteractionID: r.InteractionID, Decision: "SUBMIT"}); code != http.StatusBadRequest {
		t.Fatalf("SUBMIT to AUTHORIZE: %d", code)
	}
	nobody := &phone{e: e, key: p.key, id: p.id, token: "wrong"}
	if code, _ := nobody.answer(DeviceAnswer{InteractionID: r.InteractionID, Decision: a2h.Approve}); code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", code)
	}
	// Another principal's phone sees nothing and cannot answer.
	bob := e.pairPhone("usr_bob", "")
	if items := bob.inbox(); len(items) != 0 {
		t.Fatalf("bob sees %v", items)
	}
	if code, _ := bob.answer(DeviceAnswer{InteractionID: r.InteractionID, Decision: a2h.Approve}); code != http.StatusNotFound {
		t.Fatalf("bob answers: %d", code)
	}
	if s := e.status(r.InteractionID); s.State != a2h.StateWaitingInput {
		t.Fatalf("state %s", s.State)
	}
}

func TestAppPasskeyAndCollect(t *testing.T) {
	e := newEnv(t)
	p := e.pairPhone("usr_alice", "")

	high := e.send(e.intent(toApp, func(m *a2h.Message) { m.Assurance = &a2h.Assurance{Level: "HIGH"} }))
	e.tick()
	if it := p.inbox()[0]; it["required_factor"] != a2h.FactorPasskey {
		t.Fatalf("inbox %v", it)
	}
	if code, out := p.answer(DeviceAnswer{InteractionID: high.InteractionID, Decision: a2h.Approve}); code != http.StatusForbidden || out["error"] != "passkey_required" {
		t.Fatalf("approve HIGH: %d %v", code, out)
	}
	if code, _ := p.answer(DeviceAnswer{InteractionID: high.InteractionID, Decision: a2h.Decline}); code != 200 {
		t.Fatalf("decline HIGH: %d", code)
	}

	form := e.send(e.intent(toApp, func(m *a2h.Message) {
		m.Type = a2h.Collect
		m.Components = []a2h.Component{
			{Type: "TEXT", Name: "reason", Required: true},
			{Type: "MULTISELECT", Name: "envs", Options: []a2h.Option{{Value: "dev"}, {Value: "prod"}}},
			{Type: "CHECKBOX", Name: "notify"},
		}
	}))
	e.tick()
	code, out := p.answer(DeviceAnswer{InteractionID: form.InteractionID, Decision: "SUBMIT", Data: map[string]any{"envs": []any{"nope"}}})
	if code != http.StatusUnprocessableEntity || out["problems"].(map[string]any)["reason"] != "required" {
		t.Fatalf("invalid form: %d %v", code, out)
	}
	code, _ = p.answer(DeviceAnswer{InteractionID: form.InteractionID, Decision: "SUBMIT", Data: map[string]any{"reason": "ok", "envs": []any{"prod"}, "notify": true}})
	var resp a2h.ResponseMessage
	json.Unmarshal(e.status(form.InteractionID).Response, &resp)
	if code != 200 || resp.Data["reason"] != "ok" || resp.Data["notify"] != true || resp.Decision != "" {
		t.Fatalf("form: %d %+v", code, resp)
	}
}

func TestAppDeliveryFallsBackWithoutDevices(t *testing.T) {
	e := newEnv(t)
	r := e.send(e.intent(func(m *a2h.Message) {
		toApp(m)
		m.Channel.Fallback = []a2h.ChannelRef{{Type: "email", Address: "mailto:alice@example.com"}}
	}))
	e.tick()
	e.tick()
	if s := e.status(r.InteractionID); s.ChannelID != "email" || len(e.email.got) != 1 {
		t.Fatalf("status %+v", s)
	}
	// An address for someone else is refused rather than delivered to the wrong phone.
	e.pairPhone("usr_bob", "")
	r = e.send(e.intent(func(m *a2h.Message) { m.Channel = &a2h.Channel{Type: "app", Address: "app:usr_bob"} }))
	e.tick()
	if s := e.status(r.InteractionID); s.State != a2h.StateFailed {
		t.Fatalf("mismatched address: %+v", s)
	}
}

func TestPairing(t *testing.T) {
	e := newEnv(t)
	link, _ := e.g.CreatePairing(context.Background(), "usr_alice", time.Hour)
	code, page := e.page(link)
	if code != 200 || !strings.Contains(page, "<svg") || !strings.Contains(page, "usr_alice") {
		t.Fatalf("pair page: %d", code)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &phone{e: e, key: k}
	token := link[strings.LastIndex(link, "/")+1:]
	if code, _ := p.do("POST", "/v1/device/pair", map[string]any{"pairing_token": token, "public_key": jws.JWK{Kty: "EC", Crv: "P-256", X: "AA", Y: "AA"}}); code != http.StatusBadRequest {
		t.Fatalf("bad key: %d", code)
	}
	if code, _ := p.do("POST", "/v1/device/pair", map[string]any{"pairing_token": token, "public_key": p.jwk(), "push_url": "ftp://x"}); code != http.StatusBadRequest {
		t.Fatalf("bad push URL: %d", code)
	}
	if code, out := p.do("POST", "/v1/device/pair", map[string]any{"pairing_token": token, "public_key": p.jwk()}); code != 200 {
		t.Fatalf("pair: %d %v", code, out)
	}
	if code, _ := p.do("POST", "/v1/device/pair", map[string]any{"pairing_token": token, "public_key": p.jwk()}); code != http.StatusGone {
		t.Fatalf("reused link: %d", code)
	}
	if code, _ := e.page(link); code != http.StatusGone {
		t.Fatalf("used pair page: %d", code)
	}
	expired, _ := e.g.CreatePairing(context.Background(), "usr_alice", time.Minute)
	e.clock.Advance(2 * time.Minute)
	if code, _ := p.do("POST", "/v1/device/pair", map[string]any{"pairing_token": expired[strings.LastIndex(expired, "/")+1:], "public_key": p.jwk()}); code != http.StatusGone {
		t.Fatalf("expired link: %d", code)
	}

	q := e.pairPhone("usr_alice", "")
	if code, out := q.do("PATCH", "/v1/device", map[string]any{"push_url": "http://localhost/up", "name": "Work phone"}); code != 200 || out["push"] != true || out["name"] != "Work phone" {
		t.Fatalf("update: %d %v", code, out)
	}
	devices, _ := e.g.Devices(context.Background(), "usr_alice")
	if len(devices) != 2 || devices[1].Name != "Work phone" || !devices[1].Push {
		t.Fatalf("devices %+v", devices)
	}
	if code, _ := q.do("DELETE", "/v1/device", nil); code != 200 {
		t.Fatalf("unpair: %d", code)
	}
	if code, out := q.do("GET", "/v1/device/inbox", nil); code != http.StatusUnauthorized || out["error"] != "unpaired" {
		t.Fatalf("after unpair: %d %v", code, out)
	}
}
