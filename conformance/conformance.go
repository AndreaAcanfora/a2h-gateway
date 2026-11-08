// Package conformance checks, over the wire, how an A2H gateway implements
// the agent-facing API of the A2H v1.0 specification.
//
// The suite sends real intents: they are delivered to the address you give
// and then cancelled. Use a test address.
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/AndreaAcanfora/a2h-gateway/jws"
)

// Level says how strongly the spec requires a behaviour.
type Level string

const (
	Must   Level = "MUST"
	Should Level = "SHOULD"
	May    Level = "MAY"
)

// Result is the outcome of one check.
type Result struct {
	Name    string
	Level   Level
	Section string
	Passed  bool
	Skipped bool
	Detail  string
}

// Options configure a run.
type Options struct {
	BaseURL string
	APIKey  string
	// Channel and Address receive the test intents, e.g. "email" and
	// "mailto:a2h-test@example.com".
	Channel, Address string
	HTTP             *http.Client
}

type runner struct {
	opts    Options
	http    *http.Client
	caps    *a2h.Capabilities
	results []Result
}

// Run executes the suite.
func Run(ctx context.Context, opts Options) []Result {
	r := &runner{opts: opts, http: opts.HTTP}
	if r.http == nil {
		r.http = &http.Client{Timeout: 15 * time.Second}
	}
	r.opts.BaseURL = strings.TrimRight(r.opts.BaseURL, "/")
	r.check("discovery document", Must, "1.4", func() error { return r.discovery(ctx) })
	if r.caps == nil {
		return r.results
	}
	r.check("unauthenticated intent is refused", Should, "1.8", func() error { return r.unauthenticated(ctx) })
	r.check("RESPONSE type from an agent is rejected", Must, "1.3", func() error {
		return r.expectError(ctx, r.intent(func(m map[string]any) { m["type"] = "RESPONSE" }), 400, a2h.ErrInvalidRequest)
	})
	r.check("missing principal_id is rejected", Must, "1.2", func() error {
		return r.expectError(ctx, r.intent(func(m map[string]any) { delete(m, "principal_id") }), 400, a2h.ErrInvalidRequest)
	})
	r.check("unsupported profile is rejected", Must, "1.5", func() error {
		return r.expectError(ctx, r.intent(func(m map[string]any) { m["profile"] = "conformance.unknown.v1" }), 0, "")
	})
	r.check("ttl_sec outside 30..86400 is rejected", Must, "OpenAPI", func() error {
		return r.expectError(ctx, r.intent(func(m map[string]any) { m["ttl_sec"] = 5 }), 400, a2h.ErrInvalidRequest)
	})
	r.check("stale created_at is rejected", Should, "1.10.3", func() error {
		return r.expectError(ctx, r.intent(func(m map[string]any) {
			m["created_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		}), 0, a2h.ErrReplayRejected)
	})

	var first a2h.IntentResponse
	msg := r.intent(nil)
	r.check("valid AUTHORIZE is accepted", Must, "1.7", func() error {
		status, body, err := r.post(ctx, "/v1/intent", msg, true)
		if err != nil {
			return err
		}
		if status != 200 && status != 201 && status != 202 {
			return fmt.Errorf("status %d: %s", status, body)
		}
		if err := json.Unmarshal(body, &first); err != nil || first.InteractionID == "" {
			return fmt.Errorf("no interaction_id in %s", body)
		}
		if !validState(first.State) {
			return fmt.Errorf("unknown state %q", first.State)
		}
		return nil
	})
	if first.InteractionID == "" {
		return r.results
	}
	r.check("duplicate message_id returns the original interaction", Must, "1.10.2", func() error {
		_, body, err := r.post(ctx, "/v1/intent", msg, true)
		if err != nil {
			return err
		}
		var again a2h.IntentResponse
		json.Unmarshal(body, &again)
		if again.InteractionID != first.InteractionID {
			return fmt.Errorf("got interaction %q, want %q", again.InteractionID, first.InteractionID)
		}
		return nil
	})
	r.check("duplicate response says duplicate: true", Should, "1.10.2", func() error {
		_, body, _ := r.post(ctx, "/v1/intent", msg, true)
		var again a2h.IntentResponse
		json.Unmarshal(body, &again)
		if !again.Duplicate {
			return errors.New("duplicate is not true")
		}
		return nil
	})
	r.check("status of the interaction", Must, "1.7", func() error {
		status, body, err := r.get(ctx, "/v1/status/"+first.InteractionID, true)
		if err != nil {
			return err
		}
		var s a2h.InteractionStatus
		if status != 200 || json.Unmarshal(body, &s) != nil || s.InteractionID != first.InteractionID || !validState(s.State) {
			return fmt.Errorf("status %d: %s", status, body)
		}
		return nil
	})
	r.check("status of an unknown interaction is 404", Must, "OpenAPI", func() error {
		status, body, err := r.get(ctx, "/v1/status/"+a2h.NewID(), true)
		if err != nil {
			return err
		}
		if status != 404 {
			return fmt.Errorf("status %d: %s", status, body)
		}
		return nil
	})
	r.check("cancel a waiting interaction", Must, "1.7", func() error {
		// Give the gateway a moment to deliver, so that the interaction is waiting.
		r.waitWhilePending(ctx, first.InteractionID)
		status, body, err := r.post(ctx, "/v1/cancel/"+first.InteractionID, nil, true)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("status %d: %s", status, body)
		}
		_, body, _ = r.get(ctx, "/v1/status/"+first.InteractionID, true)
		var s a2h.InteractionStatus
		json.Unmarshal(body, &s)
		if s.State != a2h.StateCancelled {
			return fmt.Errorf("state after cancel: %s", s.State)
		}
		return nil
	})
	r.check("cancel of a terminal interaction is 409 ERR.CONFLICT", Must, "1.7", func() error {
		status, body, err := r.post(ctx, "/v1/cancel/"+first.InteractionID, nil, true)
		if err != nil {
			return err
		}
		var e a2h.APIError
		json.Unmarshal(body, &e)
		if status != 409 || e.Code != a2h.ErrConflict {
			return fmt.Errorf("status %d: %s", status, body)
		}
		return nil
	})
	r.check("nonces are single-use", May, "1.10.4", func() error { return r.nonces(ctx) })
	r.check("JWKS for RESPONSE signatures", Should, "1.11.2", func() error { return r.jwks(ctx) })
	return r.results
}

func validState(s string) bool {
	return slices.Contains([]string{a2h.StatePending, a2h.StateSent, a2h.StateWaitingInput, a2h.StateAnswered, a2h.StateExpired, a2h.StateCancelled, a2h.StateFailed}, s)
}

var errSkip = errors.New("skip")

func (r *runner) check(name string, level Level, section string, f func() error) {
	err := f()
	res := Result{Name: name, Level: level, Section: section, Passed: err == nil}
	if errors.Is(err, errSkip) {
		res.Passed, res.Skipped, res.Detail = true, true, strings.TrimPrefix(err.Error(), "skip: ")
	} else if err != nil {
		res.Detail = err.Error()
	}
	r.results = append(r.results, res)
}

func (r *runner) do(ctx context.Context, method, path string, body any, auth bool) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.opts.BaseURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth && r.opts.APIKey != "" {
		req.Header.Set(a2h.HeaderAPIKey, r.opts.APIKey)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, nil
}

func (r *runner) get(ctx context.Context, path string, auth bool) (int, []byte, error) {
	return r.do(ctx, http.MethodGet, path, nil, auth)
}

func (r *runner) post(ctx context.Context, path string, body any, auth bool) (int, []byte, error) {
	return r.do(ctx, http.MethodPost, path, body, auth)
}

func (r *runner) intent(mut func(map[string]any)) map[string]any {
	m := map[string]any{
		"a2h_version":  a2h.Version,
		"type":         a2h.Authorize,
		"message_id":   a2h.NewID(),
		"agent_id":     "did:web:a2h-conformance.invalid",
		"principal_id": "usr_a2h_conformance",
		"channel":      map[string]any{"type": r.opts.Channel, "address": r.opts.Address},
		"render":       map[string]any{"title": "A2H conformance test", "body": "This is an automated A2H conformance test. Please ignore it: it will be cancelled."},
		"ttl_sec":      120,
		"created_at":   time.Now().UTC().Format(time.RFC3339),
	}
	if mut != nil {
		mut(m)
	}
	return m
}

// expectError sends an intent that must be rejected. status 0 accepts any 4xx;
// an empty code accepts any error code.
func (r *runner) expectError(ctx context.Context, m map[string]any, status int, code string) error {
	got, body, err := r.post(ctx, "/v1/intent", m, true)
	if err != nil {
		return err
	}
	if got < 400 || got > 499 || (status != 0 && got != status) {
		// Do not leave an accepted test intent behind.
		var ok a2h.IntentResponse
		if json.Unmarshal(body, &ok) == nil && ok.InteractionID != "" {
			r.post(ctx, "/v1/cancel/"+ok.InteractionID, nil, true)
		}
		return fmt.Errorf("status %d: %s", got, bytes.TrimSpace(body))
	}
	var e a2h.APIError
	if err := json.Unmarshal(body, &e); err != nil || e.Code == "" {
		return fmt.Errorf("error body is not {\"error\": code, \"message\": …}: %s", body)
	}
	if code != "" && e.Code != code {
		return fmt.Errorf("error %s, want %s", e.Code, code)
	}
	return nil
}

func (r *runner) discovery(ctx context.Context) error {
	status, body, err := r.get(ctx, "/.well-known/a2h", false)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status %d", status)
	}
	var caps a2h.Capabilities
	if err := json.Unmarshal(body, &caps); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(body, &raw)
	for _, k := range []string{"a2h_supported", "channels", "factors"} {
		if _, ok := raw[k]; !ok {
			return fmt.Errorf("missing %q", k)
		}
	}
	if !slices.Contains(caps.A2HSupported, "1.0") {
		return fmt.Errorf("a2h_supported %v does not include 1.0", caps.A2HSupported)
	}
	if r.opts.Channel != "" && !slices.Contains(caps.Channels, r.opts.Channel) {
		return fmt.Errorf("the test channel %q is not in channels %v", r.opts.Channel, caps.Channels)
	}
	r.caps = &caps
	return nil
}

func (r *runner) unauthenticated(ctx context.Context) error {
	if r.caps.Auth != nil && len(r.caps.Auth.Methods) == 0 {
		return fmt.Errorf("%w: the gateway advertises no authentication", errSkip)
	}
	status, body, err := r.post(ctx, "/v1/intent", r.intent(nil), false)
	if err != nil {
		return err
	}
	if status != 401 && status != 403 {
		var ok a2h.IntentResponse
		if json.Unmarshal(body, &ok) == nil && ok.InteractionID != "" {
			r.post(ctx, "/v1/cancel/"+ok.InteractionID, nil, true)
		}
		return fmt.Errorf("status %d", status)
	}
	return nil
}

func (r *runner) waitWhilePending(ctx context.Context, id string) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, body, err := r.get(ctx, "/v1/status/"+id, true)
		var s a2h.InteractionStatus
		if err != nil || json.Unmarshal(body, &s) != nil || s.State != a2h.StatePending {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (r *runner) nonces(ctx context.Context) error {
	if r.caps.ReplayProtection == nil || r.caps.ReplayProtection.NonceEndpoint == "" {
		return fmt.Errorf("%w: no nonce endpoint advertised", errSkip)
	}
	status, body, err := r.get(ctx, r.caps.ReplayProtection.NonceEndpoint, true)
	if err != nil {
		return err
	}
	var n a2h.Nonce
	if status != 200 || json.Unmarshal(body, &n) != nil || n.Nonce == "" {
		return fmt.Errorf("nonce endpoint: %d %s", status, body)
	}
	withNonce := func() map[string]any {
		return r.intent(func(m map[string]any) {
			m["channel"].(map[string]any)["nonce"] = n.Nonce
		})
	}
	status, body, err = r.post(ctx, "/v1/intent", withNonce(), true)
	if err != nil {
		return err
	}
	var ok a2h.IntentResponse
	if json.Unmarshal(body, &ok) != nil || ok.InteractionID == "" {
		return fmt.Errorf("intent with a fresh nonce: %d %s", status, body)
	}
	defer r.post(ctx, "/v1/cancel/"+ok.InteractionID, nil, true)
	return r.expectError(ctx, withNonce(), 0, a2h.ErrReplayRejected)
}

func (r *runner) jwks(ctx context.Context) error {
	if r.caps.JWKSURI == "" {
		return errors.New("no jwks_uri in the discovery document")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.caps.JWKSURI, nil)
	if err != nil {
		return err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var set jws.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil || len(set.Keys) == 0 {
		return fmt.Errorf("no keys at %s", r.caps.JWKSURI)
	}
	for _, k := range set.Keys {
		if k.Kty == "EC" {
			if _, err := k.PublicKey(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Passed reports whether every MUST check passed.
func Passed(results []Result) bool {
	for _, r := range results {
		if r.Level == Must && !r.Passed {
			return false
		}
	}
	return true
}
