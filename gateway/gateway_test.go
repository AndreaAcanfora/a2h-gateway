package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/AndreaAcanfora/a2h-gateway/channels"
	"github.com/AndreaAcanfora/a2h-gateway/jws"
	"github.com/AndreaAcanfora/a2h-gateway/schemas"
)

// conforms checks a message produced or accepted by the gateway against the
// A2H JSON Schemas.
func conforms(t *testing.T, definition string, v any) {
	t.Helper()
	var b []byte
	switch x := v.(type) {
	case []byte:
		b = x
	case json.RawMessage:
		b = x
	default:
		b, _ = json.Marshal(x)
	}
	if err := schemas.Validate(definition, b); err != nil {
		t.Errorf("%s does not match the schema: %v\n%s", definition, err, b)
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// recorder is a channel that records notifications and can fail on demand.
type recorder struct {
	typ   string
	mu    sync.Mutex
	got   []channels.Notification
	fails []error // returned in order, then success
}

func (r *recorder) Type() string { return r.typ }
func (r *recorder) Deliver(_ context.Context, n channels.Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.fails) > 0 {
		err := r.fails[0]
		r.fails = r.fails[1:]
		return err
	}
	r.got = append(r.got, n)
	return nil
}
func (r *recorder) last() channels.Notification {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got[len(r.got)-1]
}

type env struct {
	t      *testing.T
	g      *Gateway
	srv    *httptest.Server
	clock  *clock
	email  *recorder
	push   *recorder
	client *a2h.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clock: &clock{t: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)}, email: &recorder{typ: "email"}, push: &recorder{typ: "push"}}
	e.srv = httptest.NewUnstartedServer(nil)
	e.srv.Start()
	var err error
	e.g, err = New(Config{
		BaseURL:          strings.Replace(e.srv.URL, "127.0.0.1", "localhost", 1),
		APIKeys:          map[string]string{"key-a": "agent-a", "key-b": "agent-b"},
		Channels:         []channels.Channel{e.email, e.push},
		Now:              e.clock.Now,
		InsecureWebhooks: true,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Config.Handler = e.g.Handler()
	e.client = a2h.NewClient(e.g.cfg.BaseURL, "key-a")
	t.Cleanup(func() { e.srv.Close(); e.g.Close() })
	return e
}

func (e *env) intent(mut ...func(*a2h.Message)) *a2h.Message {
	m := &a2h.Message{
		Type: a2h.Authorize, MessageID: a2h.NewID(), AgentID: "did:web:agent.example", PrincipalID: "usr_alice",
		Channel:           &a2h.Channel{Type: "email", Address: "mailto:alice@example.com"},
		Render:            &a2h.Render{Title: "Delete files?", Body: "Delete 3 unused files."},
		ExplanationBundle: map[string]any{"why": "This is irreversible."},
		TTLSec:            300,
		CreatedAt:         e.clock.Now().Format(time.RFC3339),
	}
	for _, f := range mut {
		f(m)
	}
	return m
}

func (e *env) send(m *a2h.Message) *a2h.IntentResponse {
	e.t.Helper()
	r, err := e.client.Send(context.Background(), m)
	if err != nil {
		e.t.Fatalf("send: %v", err)
	}
	return r
}

func (e *env) sendErr(m *a2h.Message) *a2h.APIError {
	e.t.Helper()
	_, err := e.client.Send(context.Background(), m)
	var apiErr *a2h.APIError
	if !errors.As(err, &apiErr) {
		e.t.Fatalf("expected an API error, got %v", err)
	}
	return apiErr
}

func (e *env) status(id string) *a2h.InteractionStatus {
	e.t.Helper()
	s, err := e.client.Status(context.Background(), id)
	if err != nil {
		e.t.Fatalf("status: %v", err)
	}
	return s
}

func (e *env) tick() { e.g.Tick(context.Background()) }

// page fetches the human page behind the last notification.
func (e *env) page(url string) (int, string) {
	resp, err := http.Get(url)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) post(u string, form url.Values) (int, string) {
	resp, err := http.PostForm(u, form)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestDiscoveryAndJWKS(t *testing.T) {
	e := newEnv(t)
	caps, err := e.client.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.A2HSupported[0] != "1.0" || strings.Join(caps.Channels, ",") != "app,email,push" || caps.JWKSURI != e.g.cfg.BaseURL+"/.well-known/jwks.json" {
		t.Errorf("capabilities %+v", caps)
	}
	conforms(t, "Capabilities", caps)
	if caps.ReplayProtection.IdempotencyWindowSec != 3600 || caps.Webhooks.RetryAttempts != 3 || caps.Auth.Methods[0] != "api_key" {
		t.Errorf("capabilities %+v", caps)
	}
	keys, err := e.client.JWKS(context.Background())
	if err != nil || len(keys.Keys) != 1 || keys.Keys[0].Kid != e.g.Key().ID {
		t.Fatalf("jwks %v %v", keys, err)
	}
}

func TestAuthentication(t *testing.T) {
	e := newEnv(t)
	anon := a2h.NewClient(e.srv.URL, "")
	_, err := anon.Send(context.Background(), e.intent())
	var apiErr *a2h.APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != 401 {
		t.Fatalf("no key: %v", err)
	}
	wrong := a2h.NewClient(e.srv.URL, "nope")
	if _, err := wrong.Status(context.Background(), "x"); !errors.As(err, &apiErr) || apiErr.HTTPStatus != 401 {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestValidation(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name   string
		mut    func(*a2h.Message)
		code   string
		status int
	}{
		{"response type", func(m *a2h.Message) { m.Type = a2h.Response }, a2h.ErrInvalidRequest, 400},
		{"unknown type", func(m *a2h.Message) { m.Type = "PING" }, a2h.ErrInvalidRequest, 400},
		{"no principal", func(m *a2h.Message) { m.PrincipalID = "" }, a2h.ErrInvalidRequest, 400},
		{"no channel", func(m *a2h.Message) { m.Channel = nil }, a2h.ErrInvalidRequest, 400},
		{"unavailable channel", func(m *a2h.Message) { m.Channel.Type = "sms"; m.Channel.Address = "tel:+1555" }, a2h.ErrChannelUnavailable, 422},
		{"address scheme", func(m *a2h.Message) { m.Channel.Address = "alice@example.com" }, a2h.ErrInvalidRequest, 400},
		{"no body", func(m *a2h.Message) { m.Render = nil }, a2h.ErrInvalidRequest, 400},
		{"ttl too short", func(m *a2h.Message) { m.TTLSec = 10 }, a2h.ErrInvalidRequest, 400},
		{"ttl too long", func(m *a2h.Message) { m.TTLSec = 90000 }, a2h.ErrInvalidRequest, 400},
		{"profile", func(m *a2h.Message) { m.Profile = "transaction.v1" }, a2h.ErrInvalidRequest, 400},
		{"factor", func(m *a2h.Message) { m.Assurance = &a2h.Assurance{RequiredFactors: []string{"otp.sms.v1"}} }, a2h.ErrInvalidRequest, 400},
		{"callback secret", func(m *a2h.Message) { m.Callback = &a2h.Callback{URL: "https://a.example/hook"} }, a2h.ErrInvalidRequest, 400},
		{"collect without components", func(m *a2h.Message) { m.Type = a2h.Collect }, a2h.ErrInvalidRequest, 400},
		{"future version", func(m *a2h.Message) { m.A2HMinVersion = "1.1" }, a2h.ErrInvalidRequest, 400},
		{"stale timestamp", func(m *a2h.Message) { m.CreatedAt = e.clock.Now().Add(-10 * time.Minute).Format(time.RFC3339) }, a2h.ErrReplayRejected, 400},
		{"future timestamp", func(m *a2h.Message) { m.CreatedAt = e.clock.Now().Add(10 * time.Minute).Format(time.RFC3339) }, a2h.ErrReplayRejected, 400},
	}
	for _, c := range cases {
		err := e.sendErr(e.intent(c.mut))
		conforms(t, "ErrorResponse", err)
		if err.Code != c.code || err.HTTPStatus != c.status {
			t.Errorf("%s: got %s %d (%s), want %s %d", c.name, err.Code, err.HTTPStatus, err.Message, c.code, c.status)
		}
	}
}

func TestApproveThroughLink(t *testing.T) {
	e := newEnv(t)
	m := e.intent()
	r := e.send(m)
	conforms(t, "Message", m)
	conforms(t, "IntentResponse", r)
	if r.State != a2h.StatePending || r.TTLSec != 300 {
		t.Fatalf("intent response %+v", r)
	}
	e.tick()
	s := e.status(r.InteractionID)
	if s.State != a2h.StateWaitingInput || s.ChannelID != "email" || s.ExpiresAt != "2026-11-08T10:05:00Z" {
		t.Fatalf("after delivery: %+v", s)
	}
	n := e.email.last()
	if n.Address != "mailto:alice@example.com" || n.Why != "This is irreversible." || !strings.HasPrefix(n.ActionURL, e.g.cfg.BaseURL+"/i/") || n.ExpiresAt.IsZero() {
		t.Fatalf("notification %+v", n)
	}
	code, html := e.page(n.ActionURL)
	if code != 200 || !strings.Contains(html, "Delete 3 unused files.") || !strings.Contains(html, `value="APPROVE"`) {
		t.Fatalf("page %d:\n%s", code, html)
	}
	code, html = e.post(n.ActionURL, url.Values{"decision": {"APPROVE"}})
	if code != 200 || !strings.Contains(html, "You approved this request") {
		t.Fatalf("after approve %d:\n%s", code, html)
	}
	s = e.status(r.InteractionID)
	if s.State != a2h.StateAnswered {
		t.Fatalf("state %s", s.State)
	}
	conforms(t, "InteractionStatus", s)
	conforms(t, "Response", s.Response)
	resp, err := e.client.VerifyResponse(context.Background(), s.Response, m.MessageID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if resp.Decision != a2h.Approve || resp.InteractionID != r.InteractionID || resp.PrincipalID != "usr_alice" || resp.Evidence.Factor != a2h.FactorEmailLink {
		t.Fatalf("response %+v", resp)
	}
	if resp.Evidence.Proof["delivery_channel"] != "mailto:alice@example.com" {
		t.Errorf("proof %v", resp.Evidence.Proof)
	}
	// Single-use link: a second answer changes nothing.
	code, _ = e.post(n.ActionURL, url.Values{"decision": {"DECLINE"}})
	if code != 410 {
		t.Errorf("reused link: %d", code)
	}
	if again := e.status(r.InteractionID); !bytes.Equal(again.Response, s.Response) {
		t.Error("the response changed after a second answer")
	}
	// Tampering is detected.
	tampered := bytes.Replace(s.Response, []byte(`"APPROVE"`), []byte(`"DECLINE"`), 1)
	if _, err := e.client.VerifyResponse(context.Background(), tampered, m.MessageID); !errors.Is(err, jws.ErrInvalid) {
		t.Errorf("tampered response: %v", err)
	}
	if _, err := e.client.VerifyResponse(context.Background(), s.Response, "other-message"); err == nil {
		t.Error("response accepted for another message")
	}
}

func TestDecline(t *testing.T) {
	e := newEnv(t)
	r := e.send(e.intent())
	e.tick()
	e.post(e.email.last().ActionURL, url.Values{"decision": {"DECLINE"}})
	var resp a2h.ResponseMessage
	json.Unmarshal(e.status(r.InteractionID).Response, &resp)
	if resp.Decision != a2h.Decline {
		t.Errorf("decision %q", resp.Decision)
	}
}

// postAs sends a form POST with the headers a browser would set.
func postAs(t *testing.T, link string, headers map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", link, strings.NewReader("decision=APPROVE"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestOriginChecks(t *testing.T) {
	e := newEnv(t)
	refused := []map[string]string{
		{"Origin": "https://evil.example"},
		{"Origin": "null", "Sec-Fetch-Site": "cross-site"},
		{"Origin": "null"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Origin": e.g.origin, "Sec-Fetch-Site": "same-site"},
	}
	e.send(e.intent())
	e.tick()
	link := e.email.last().ActionURL
	for _, h := range refused {
		if code := postAs(t, link, h); code != 403 {
			t.Errorf("%v: %d, want 403", h, code)
		}
	}
	// What browsers send for the gateway's own form, depending on policies.
	accepted := []map[string]string{
		{"Origin": e.g.origin, "Sec-Fetch-Site": "same-origin"},
		{"Origin": "null", "Sec-Fetch-Site": "same-origin"},
		{},
	}
	for _, h := range accepted {
		e.send(e.intent())
		e.tick()
		if code := postAs(t, e.email.last().ActionURL, h); code != 200 {
			t.Errorf("%v: %d, want 200", h, code)
		}
	}
}

func TestUnknownLink(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.page(e.srv.URL + "/i/not-a-token"); code != 404 {
		t.Errorf("unknown link: %d", code)
	}
}

func TestIdempotencyAndIsolation(t *testing.T) {
	e := newEnv(t)
	m := e.intent()
	first := e.send(m)
	again := e.send(m)
	if !again.Duplicate || again.InteractionID != first.InteractionID {
		t.Fatalf("duplicate: %+v vs %+v", again, first)
	}
	// Same message_id from another agent is a different message.
	other := a2h.NewClient(e.srv.URL, "key-b")
	r2, err := other.Send(context.Background(), m)
	if err != nil || r2.Duplicate || r2.InteractionID == first.InteractionID {
		t.Fatalf("other agent: %+v %v", r2, err)
	}
	// Agents cannot read each other's interactions.
	var apiErr *a2h.APIError
	if _, err := other.Status(context.Background(), first.InteractionID); !errors.As(err, &apiErr) || apiErr.HTTPStatus != 404 {
		t.Errorf("cross-agent status: %v", err)
	}
	// After the window, the message_id is new again.
	e.clock.Advance(61 * time.Minute)
	e.g.store.cleanup(context.Background(), e.clock.Now(), time.Hour)
	m.CreatedAt = e.clock.Now().Format(time.RFC3339)
	if late := e.send(m); late.Duplicate {
		t.Error("duplicate after the idempotency window")
	}
}

func TestNonces(t *testing.T) {
	e := newEnv(t)
	n, err := e.client.GetNonce(context.Background())
	if err != nil || len(n.Nonce) < 32 {
		t.Fatalf("nonce %+v %v", n, err)
	}
	e.send(e.intent(func(m *a2h.Message) { m.Channel.Nonce = n.Nonce }))
	if err := e.sendErr(e.intent(func(m *a2h.Message) { m.Channel.Nonce = n.Nonce })); err.Code != a2h.ErrReplayRejected {
		t.Errorf("reused nonce: %v", err)
	}
	if err := e.sendErr(e.intent(func(m *a2h.Message) { m.Channel.Nonce = "made-up" })); err.Code != a2h.ErrReplayRejected {
		t.Errorf("unknown nonce: %v", err)
	}
	n2, _ := e.client.GetNonce(context.Background())
	e.clock.Advance(6 * time.Minute)
	if err := e.sendErr(e.intent(func(m *a2h.Message) { m.Channel.Nonce = n2.Nonce })); err.Code != a2h.ErrReplayRejected {
		t.Errorf("expired nonce: %v", err)
	}
}

type hookServer struct {
	*httptest.Server
	mu       sync.Mutex
	statuses []int
	bodies   [][]byte
	headers  []http.Header
}

func newHook(t *testing.T, statuses ...int) *hookServer {
	h := &hookServer{statuses: statuses}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.bodies = append(h.bodies, b)
		h.headers = append(h.headers, r.Header.Clone())
		status := 200
		if len(h.statuses) > 0 {
			status, h.statuses = h.statuses[0], h.statuses[1:]
		}
		h.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(h.Close)
	return h
}

func TestWebhookDeliveryAndRetries(t *testing.T) {
	e := newEnv(t)
	hook := newHook(t, 500, 503)
	m := e.intent(func(m *a2h.Message) { m.Callback = &a2h.Callback{URL: hook.URL, Secret: "whsec_test"} })
	r := e.send(m)
	e.tick()
	e.post(e.email.last().ActionURL, url.Values{"decision": {"APPROVE"}})
	e.tick() // attempt 1: 500
	e.clock.Advance(10 * time.Second)
	e.tick() // attempt 2: 503
	e.clock.Advance(59 * time.Second)
	e.tick() // not due yet
	if len(hook.bodies) != 2 {
		t.Fatalf("%d deliveries before the third attempt is due", len(hook.bodies))
	}
	e.clock.Advance(time.Second)
	e.tick() // attempt 3: 200
	if len(hook.bodies) != 3 {
		t.Fatalf("%d deliveries", len(hook.bodies))
	}
	ids := map[string]bool{}
	for i, h := range hook.headers {
		ids[h.Get(a2h.HeaderDeliveryID)] = true
		if err := a2h.VerifyWebhook("whsec_test", h.Get(a2h.HeaderSignature), hook.bodies[i], e.clock.Now(), 5*time.Minute); err != nil {
			t.Errorf("attempt %d signature: %v", i+1, err)
		}
	}
	if len(ids) != 1 {
		t.Errorf("delivery ID changed across retries: %v", ids)
	}
	if _, err := e.client.VerifyResponse(context.Background(), hook.bodies[2], m.MessageID); err != nil {
		t.Errorf("webhook body: %v", err)
	}
	if e.status(r.InteractionID).WebhookFailed {
		t.Error("marked failed after success")
	}
}

func TestWebhookGivesUp(t *testing.T) {
	e := newEnv(t)
	hook := newHook(t, 500, 500, 500, 500)
	r := e.send(e.intent(func(m *a2h.Message) { m.Callback = &a2h.Callback{URL: hook.URL, Secret: "s"} }))
	e.tick()
	e.post(e.email.last().ActionURL, url.Values{"decision": {"APPROVE"}})
	for _, d := range []time.Duration{0, 10 * time.Second, time.Minute, 5 * time.Minute} {
		e.clock.Advance(d)
		e.tick()
	}
	if len(hook.bodies) != 4 || !e.status(r.InteractionID).WebhookFailed {
		t.Fatalf("%d attempts, failed=%v", len(hook.bodies), e.status(r.InteractionID).WebhookFailed)
	}
}

func TestExpiry(t *testing.T) {
	e := newEnv(t)
	hook := newHook(t)
	m := e.intent(func(m *a2h.Message) {
		m.TTLSec = 60
		m.Callback = &a2h.Callback{URL: hook.URL, Secret: "s"}
	})
	r := e.send(m)
	e.tick()
	link := e.email.last().ActionURL
	e.clock.Advance(61 * time.Second)
	// Read before the sweep: the status is already right.
	s := e.status(r.InteractionID)
	if s.State != a2h.StateExpired || s.Error == nil || s.Error.Code != a2h.ErrExpired {
		t.Fatalf("status %+v", s)
	}
	code, html := e.post(link, url.Values{"decision": {"APPROVE"}})
	if code != 410 || !strings.Contains(html, "expired") {
		t.Errorf("late answer %d", code)
	}
	e.tick()
	if len(hook.bodies) != 1 {
		t.Fatalf("%d webhooks", len(hook.bodies))
	}
	conforms(t, "ErrorMessage", hook.bodies[0])
	conforms(t, "InteractionStatus", s)
	var errMsg a2h.ErrorMessage
	json.Unmarshal(hook.bodies[0], &errMsg)
	if errMsg.Type != a2h.Error || errMsg.Error.Code != a2h.ErrExpired || errMsg.RespondsTo != m.MessageID {
		t.Errorf("error message %+v", errMsg)
	}
	keys, _ := e.client.JWKS(context.Background())
	if err := jws.Verify(hook.bodies[0], *keys); err != nil {
		t.Errorf("error message signature: %v", err)
	}
}

func TestCancel(t *testing.T) {
	e := newEnv(t)
	r := e.send(e.intent())
	e.tick()
	if err := e.client.Cancel(context.Background(), r.InteractionID); err != nil {
		t.Fatal(err)
	}
	if s := e.status(r.InteractionID); s.State != a2h.StateCancelled {
		t.Fatalf("state %s", s.State)
	}
	var apiErr *a2h.APIError
	if err := e.client.Cancel(context.Background(), r.InteractionID); !errors.As(err, &apiErr) || apiErr.Code != a2h.ErrConflict {
		t.Errorf("second cancel: %v", err)
	}
	if code, html := e.page(e.email.last().ActionURL); code != 410 || !strings.Contains(html, "cancelled") {
		t.Errorf("page after cancel: %d", code)
	}
	// Cancelling before delivery prevents it.
	before := len(e.email.got)
	r2 := e.send(e.intent())
	e.client.Cancel(context.Background(), r2.InteractionID)
	e.tick()
	if len(e.email.got) != before {
		t.Error("a cancelled intent was delivered")
	}
}

func TestDeliveryRetriesAndFallback(t *testing.T) {
	e := newEnv(t)
	transient := errors.New("smtp timeout")
	e.email.fails = []error{transient, transient, transient, transient}
	r := e.send(e.intent(func(m *a2h.Message) {
		m.Channel.Fallback = []a2h.ChannelRef{{Type: "push", Address: "https://ntfy.example/alice"}}
	}))
	for _, d := range []time.Duration{0, 10 * time.Second, 30 * time.Second, 2 * time.Minute} {
		e.clock.Advance(d)
		e.tick()
		if s := e.status(r.InteractionID); s.State != a2h.StatePending {
			t.Fatalf("state %s during email retries", s.State)
		}
	}
	e.tick() // fallback to push, immediately
	s := e.status(r.InteractionID)
	if s.State != a2h.StateWaitingInput || s.ChannelID != "push" || len(e.push.got) != 1 {
		t.Fatalf("after fallback: %+v", s)
	}
	// The link works the same, with link.v1 evidence.
	e.post(e.push.last().ActionURL, url.Values{"decision": {"APPROVE"}})
	var resp a2h.ResponseMessage
	json.Unmarshal(e.status(r.InteractionID).Response, &resp)
	if resp.Evidence.Factor != a2h.FactorLink || resp.Evidence.Proof["delivery_channel"] != "https://ntfy.example/alice" {
		t.Errorf("evidence %+v", resp.Evidence)
	}
}

func TestPermanentFailure(t *testing.T) {
	e := newEnv(t)
	hook := newHook(t)
	e.email.fails = []error{channels.Permanent(errors.New("550 no such user"))}
	r := e.send(e.intent(func(m *a2h.Message) { m.Callback = &a2h.Callback{URL: hook.URL, Secret: "s"} }))
	e.tick()
	s := e.status(r.InteractionID)
	if s.State != a2h.StateFailed || s.Error.Code != a2h.ErrDeliveryFailed || !strings.Contains(s.Error.Message, "550") {
		t.Fatalf("status %+v", s)
	}
	e.tick()
	if len(hook.bodies) != 1 || !bytes.Contains(hook.bodies[0], []byte(a2h.ErrDeliveryFailed)) {
		t.Errorf("webhook %s", hook.bodies)
	}
}

func TestCollect(t *testing.T) {
	e := newEnv(t)
	min, max := 1.0, 9.0
	m := e.intent(func(m *a2h.Message) {
		m.Type = a2h.Collect
		m.Render = &a2h.Render{Body: "Book the table"}
		m.Components = []a2h.Component{
			{Type: "TEXT", Name: "full_name", Label: "Full name", Required: true},
			{Type: "SELECT", Name: "slot", Required: true, Options: []a2h.Option{{Value: "tue_2pm", Label: "Tue 2pm"}, {Value: "wed_9am", Label: "Wed 9am"}}},
			{Type: "NUMBER", Name: "guests", Validation: &a2h.Validation{Min: &min, Max: &max}},
			{Type: "CHECKBOX", Name: "vegan"},
			{Type: "MULTISELECT", Name: "extras", Options: []a2h.Option{{Value: "cake"}, {Value: "wine"}}},
		}
	})
	r := e.send(m)
	e.tick()
	link := e.email.last().ActionURL
	if _, html := e.page(link); !strings.Contains(html, `<option value="wed_9am" >Wed 9am</option>`) {
		t.Fatalf("form:\n%s", html)
	}
	code, html := e.post(link, url.Values{"decision": {"SUBMIT"}, "full_name": {"Jane"}, "slot": {"fri"}, "guests": {"20"}})
	if code != 422 || !strings.Contains(html, "not one of the options") || !strings.Contains(html, "out of range") || !strings.Contains(html, `value="Jane"`) {
		t.Fatalf("invalid form %d:\n%s", code, html)
	}
	e.post(link, url.Values{"decision": {"SUBMIT"}, "full_name": {"Jane Doe"}, "slot": {"wed_9am"}, "guests": {"2"}, "vegan": {"on"}, "extras": {"cake", "wine"}})
	var resp a2h.ResponseMessage
	conforms(t, "Response", e.status(r.InteractionID).Response)
	json.Unmarshal(e.status(r.InteractionID).Response, &resp)
	want := `{"extras":["cake","wine"],"full_name":"Jane Doe","guests":2,"slot":"wed_9am","vegan":true}`
	if got, _ := json.Marshal(resp.Data); string(got) != want || resp.Decision != "" {
		t.Errorf("data %s decision %q", got, resp.Decision)
	}
}

func TestInformAndFollowUps(t *testing.T) {
	e := newEnv(t)
	auth := e.send(e.intent())
	e.tick()
	e.post(e.email.last().ActionURL, url.Values{"decision": {"APPROVE"}})

	// A RESULT in the same interaction is delivered; the AUTHORIZE keeps its state.
	res := e.send(e.intent(func(m *a2h.Message) {
		m.Type, m.InteractionID = a2h.Result, auth.InteractionID
		m.Render = &a2h.Render{Body: "Done: 3 files deleted."}
	}))
	if res.InteractionID != auth.InteractionID {
		t.Fatalf("follow-up got interaction %s", res.InteractionID)
	}
	e.tick()
	if e.email.last().Body != "Done: 3 files deleted." || e.status(auth.InteractionID).State != a2h.StateAnswered {
		t.Fatal("follow-up not delivered, or it changed the interaction")
	}
	if code, html := e.page(e.email.last().ActionURL); code != 200 || !strings.Contains(html, "Done: 3 files deleted.") || strings.Contains(html, "<form") {
		t.Errorf("result page %d", code)
	}
	// Asking again inside the same interaction is a conflict.
	if err := e.sendErr(e.intent(func(m *a2h.Message) { m.InteractionID = auth.InteractionID })); err.Code != a2h.ErrConflict {
		t.Errorf("second AUTHORIZE: %v", err)
	}

	inform := e.send(e.intent(func(m *a2h.Message) { m.Type = a2h.Inform }))
	e.tick()
	s := e.status(inform.InteractionID)
	if s.State != a2h.StateSent || !a2h.Terminal(s.State, s.Type) || s.ExpiresAt != "" {
		t.Errorf("inform status %+v", s)
	}
	var apiErr *a2h.APIError
	if err := e.client.Cancel(context.Background(), inform.InteractionID); !errors.As(err, &apiErr) || apiErr.Code != a2h.ErrConflict {
		t.Errorf("cancel delivered INFORM: %v", err)
	}
}

func TestPasskeyRequired(t *testing.T) {
	e := newEnv(t)
	r := e.send(e.intent(func(m *a2h.Message) { m.Assurance = &a2h.Assurance{Level: "HIGH"} }))
	e.tick()
	link := e.email.last().ActionURL
	_, html := e.page(link)
	if !strings.Contains(html, "none is enrolled for you yet") || strings.Contains(html, `id="approve-passkey"`) {
		t.Fatalf("page without passkey:\n%s", html)
	}
	if code, _ := e.post(link, url.Values{"decision": {"APPROVE"}}); code != 422 {
		t.Errorf("link approval of a HIGH request: %d", code)
	}
	resp, _ := http.Post(link+"/passkey/options", "application/json", nil)
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Errorf("options without passkey: %d", resp.StatusCode)
	}
	// Declining needs no passkey.
	e.post(link, url.Values{"decision": {"DECLINE"}})
	if s := e.status(r.InteractionID); s.State != a2h.StateAnswered {
		t.Errorf("decline: %s", s.State)
	}
}

func TestEnrollmentLink(t *testing.T) {
	e := newEnv(t)
	u, err := e.g.CreateEnrollment(context.Background(), "usr_alice", time.Hour)
	if err != nil || !regexp.MustCompile(`/enroll/[A-Za-z0-9_-]{43}$`).MatchString(u) {
		t.Fatalf("enrollment %q %v", u, err)
	}
	if code, html := e.page(u); code != 200 || !strings.Contains(html, "usr_alice") {
		t.Errorf("enroll page %d", code)
	}
	resp, _ := http.Post(u+"/options", "application/json", nil)
	var opts map[string]any
	json.NewDecoder(resp.Body).Decode(&opts)
	resp.Body.Close()
	pk, _ := opts["publicKey"].(map[string]any)
	if resp.StatusCode != 200 || pk["challenge"] == nil {
		t.Errorf("options %d %v", resp.StatusCode, opts)
	}
	e.clock.Advance(2 * time.Hour)
	if code, _ := e.page(u); code != 410 {
		t.Errorf("expired enrollment: %d", code)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	e.g.cfg.RateLimitPerMinute = 2
	e.send(e.intent())
	e.send(e.intent())
	err := e.sendErr(e.intent())
	if err.Code != a2h.ErrRateLimited || err.HTTPStatus != 429 || err.RetryAfterSec < 1 {
		t.Errorf("rate limit %+v", err)
	}
	e.clock.Advance(time.Minute)
	e.send(e.intent(func(m *a2h.Message) { m.CreatedAt = e.clock.Now().Format(time.RFC3339) }))
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	open := func() *Gateway {
		g, err := New(Config{BaseURL: "https://a2h.example", DataDir: dir, APIKeys: map[string]string{"k": "a"}, Channels: []channels.Channel{&recorder{typ: "email"}}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g1 := open()
	kid, token := g1.Key().ID, g1.linkToken("x")
	g1.Close()
	g2 := open()
	defer g2.Close()
	if g2.Key().ID != kid || g2.linkToken("x") != token {
		t.Error("key or link secret changed across restarts")
	}
}

func TestInMemoryStoresAreSeparate(t *testing.T) {
	a, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, _ := OpenStore(":memory:")
	defer b.Close()
	a.addJob(context.Background(), a.db, job{Kind: "deliver", InteractionID: "x", RunAt: time.Unix(0, 0)})
	if jobs, _ := b.takeDueJobs(context.Background(), time.Now(), 10); len(jobs) != 0 {
		t.Fatal("a job added to one in-memory store appeared in another")
	}
}
