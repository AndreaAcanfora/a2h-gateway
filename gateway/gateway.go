// Package gateway is a self-hosted A2H gateway: it accepts intents from
// agents, delivers them to people over their channels, collects decisions
// with evidence, signs the RESPONSE and reports it back by webhook or polling.
package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/AndreaAcanfora/a2h-gateway/channels"
	"github.com/AndreaAcanfora/a2h-gateway/jws"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config configures a Gateway.
type Config struct {
	// BaseURL is the public URL people open, e.g. https://a2h.example.com.
	BaseURL string
	// DataDir holds the database, the signing key and the link secret.
	// Empty means in memory, with a new key on each start (tests only).
	DataDir string
	// APIKeys maps API keys to the name of the agent that uses them.
	APIKeys map[string]string
	// NoAuth accepts requests without an API key. Development only.
	NoAuth   bool
	Channels []channels.Channel

	MaxTTLSec          int
	IdempotencyWindow  time.Duration
	TimestampTolerance time.Duration
	RateLimitPerMinute int
	// InsecureWebhooks accepts http:// callback URLs. Development only.
	InsecureWebhooks bool
	DeliveryRetry    []time.Duration
	WebhookRetry     []time.Duration
	WebhookTimeout   time.Duration

	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time
}

// Gateway is an A2H gateway. Create it with New, serve Handler, and run Run.
type Gateway struct {
	cfg        Config
	store      *Store
	key        *jws.Key
	linkSecret []byte
	webauthn   *webauthn.WebAuthn
	channels   map[string]channels.Channel
	log        *slog.Logger
	origin     string
	mux        *http.ServeMux

	rateMu sync.Mutex
	rate   map[string]*window
}

type window struct {
	start time.Time
	count int
}

// New opens the gateway's state and returns it.
func New(cfg Config) (*Gateway, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("gateway: BaseURL must be an absolute http(s) URL, got %q", cfg.BaseURL)
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if net.ParseIP(u.Hostname()) != nil {
		return nil, fmt.Errorf("gateway: BaseURL must use a host name, not an IP address: passkeys are bound to domain names (use http://localhost:PORT for local development)")
	}
	if cfg.MaxTTLSec == 0 {
		cfg.MaxTTLSec = 86400
	}
	if cfg.IdempotencyWindow == 0 {
		cfg.IdempotencyWindow = time.Hour
	}
	if cfg.TimestampTolerance == 0 {
		cfg.TimestampTolerance = 5 * time.Minute
	}
	if cfg.RateLimitPerMinute == 0 {
		cfg.RateLimitPerMinute = 60
	}
	if cfg.DeliveryRetry == nil {
		// Spec section 1.13.4: immediate, 10 s, 30 s, 2 min.
		cfg.DeliveryRetry = []time.Duration{0, 10 * time.Second, 30 * time.Second, 2 * time.Minute}
	}
	if cfg.WebhookRetry == nil {
		// Spec section 1.12.5: immediate, 10 s, 60 s, 5 min.
		cfg.WebhookRetry = []time.Duration{0, 10 * time.Second, time.Minute, 5 * time.Minute}
	}
	if cfg.WebhookTimeout == 0 {
		cfg.WebhookTimeout = 30 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.WebhookTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if len(cfg.APIKeys) == 0 && !cfg.NoAuth {
		return nil, errors.New("gateway: no API keys configured (set some, or enable NoAuth for development)")
	}

	g := &Gateway{cfg: cfg, log: cfg.Logger, channels: map[string]channels.Channel{}, rate: map[string]*window{}, origin: u.Scheme + "://" + u.Host}
	for _, c := range cfg.Channels {
		g.channels[c.Type()] = c
	}
	dbPath := ":memory:"
	if cfg.DataDir != "" {
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			return nil, err
		}
		dbPath = filepath.Join(cfg.DataDir, "a2h.db")
	}
	if g.store, err = OpenStore(dbPath); err != nil {
		return nil, err
	}
	if g.key, err = loadOrCreateKey(cfg.DataDir); err != nil {
		return nil, err
	}
	if g.linkSecret, err = loadOrCreateSecret(cfg.DataDir); err != nil {
		return nil, err
	}
	g.webauthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "A2H Gateway",
		RPID:          u.Hostname(),
		RPOrigins:     []string{g.origin},
	})
	if err != nil {
		return nil, fmt.Errorf("gateway: webauthn: %w", err)
	}
	g.routes()
	return g, nil
}

// Close releases the database.
func (g *Gateway) Close() error { return g.store.Close() }

// Handler returns the HTTP handler of the gateway.
func (g *Gateway) Handler() http.Handler { return g.mux }

// Key returns the gateway's signing key.
func (g *Gateway) Key() *jws.Key { return g.key }

func loadOrCreateKey(dir string) (*jws.Key, error) {
	if dir == "" {
		return jws.GenerateKey()
	}
	path := filepath.Join(dir, "signing-key.pem")
	if data, err := os.ReadFile(path); err == nil {
		return jws.ParsePEM(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := jws.GenerateKey()
	if err != nil {
		return nil, err
	}
	p, err := k.MarshalPEM()
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, p, 0o600)
}

func loadOrCreateSecret(dir string) ([]byte, error) {
	secret := make([]byte, 32)
	if dir == "" {
		_, err := rand.Read(secret)
		return secret, err
	}
	path := filepath.Join(dir, "link-secret")
	if data, err := os.ReadFile(path); err == nil {
		return hex.DecodeString(strings.TrimSpace(string(data)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	rand.Read(secret)
	return secret, os.WriteFile(path, []byte(hex.EncodeToString(secret)), 0o600)
}

// linkToken is the secret in the URL a principal opens. It is derived from
// the interaction ID, so it never has to be stored: only its hash is.
func (g *Gateway) linkToken(interactionID string) string {
	mac := hmac.New(sha256.New, g.linkSecret)
	mac.Write([]byte("link:" + interactionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (g *Gateway) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /.well-known/a2h", g.handleDiscovery)
	m.HandleFunc("GET /.well-known/jwks.json", g.handleJWKS)
	m.HandleFunc("POST /v1/intent", g.api(g.handleIntent))
	m.HandleFunc("GET /v1/status/{id}", g.api(g.handleStatus))
	m.HandleFunc("POST /v1/cancel/{id}", g.api(g.handleCancel))
	m.HandleFunc("GET /v1/nonce", g.api(g.handleNonce))
	m.HandleFunc("GET /i/{token}", g.handlePage)
	m.HandleFunc("POST /i/{token}", g.handleAnswer)
	m.HandleFunc("POST /i/{token}/passkey/options", g.handlePasskeyOptions)
	m.HandleFunc("POST /i/{token}/passkey/verify", g.handlePasskeyVerify)
	m.HandleFunc("GET /enroll/{token}", g.handleEnrollPage)
	m.HandleFunc("POST /enroll/{token}/options", g.handleEnrollOptions)
	m.HandleFunc("POST /enroll/{token}/verify", g.handleEnrollVerify)
	m.HandleFunc("GET /pair/{token}", g.handlePairPage)
	m.HandleFunc("POST /v1/device/pair", g.handlePair)
	m.HandleFunc("GET /v1/device", g.deviceAPI(g.handleDevice))
	m.HandleFunc("PATCH /v1/device", g.deviceAPI(g.handleDeviceUpdate))
	m.HandleFunc("DELETE /v1/device", g.deviceAPI(g.handleUnpair))
	m.HandleFunc("GET /v1/device/inbox", g.deviceAPI(g.handleInbox))
	m.HandleFunc("POST /v1/device/answer", g.deviceAPI(g.handleDeviceAnswer))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	g.mux = m
}

// Capabilities returns the discovery document.
func (g *Gateway) Capabilities() a2h.Capabilities {
	chans := []string{AppChannel}
	for t := range g.channels {
		chans = append(chans, t)
	}
	slices.Sort(chans)
	methods := []string{"api_key"}
	if g.cfg.NoAuth {
		methods = []string{}
	}
	return a2h.Capabilities{
		A2HSupported: []string{a2h.Version},
		Channels:     chans,
		Factors:      []string{a2h.FactorPasskey, a2h.FactorDeviceKey, a2h.FactorEmailLink, a2h.FactorLink},
		MaxTTLSec:    g.cfg.MaxTTLSec,
		Locales:      []string{"en"},
		JWKSURI:      g.cfg.BaseURL + "/.well-known/jwks.json",
		Auth:         &a2h.AuthInfo{Methods: methods},
		ReplayProtection: &a2h.ReplayProtection{
			IdempotencyWindowSec:  int(g.cfg.IdempotencyWindow / time.Second),
			TimestampToleranceSec: int(g.cfg.TimestampTolerance / time.Second),
			NonceEndpoint:         "/v1/nonce",
		},
		Webhooks: &a2h.WebhookInfo{Supported: true, RetryAttempts: len(g.cfg.WebhookRetry) - 1, TimeoutSec: int(g.cfg.WebhookTimeout / time.Second)},
		Profiles: []string{},
	}
}

func (g *Gateway) limits() a2h.Limits {
	caps := g.Capabilities()
	return a2h.Limits{MaxTTLSec: g.cfg.MaxTTLSec, Channels: caps.Channels, Factors: caps.Factors, InsecureWebhook: g.cfg.InsecureWebhooks}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, e *a2h.APIError) {
	status := e.HTTPStatus
	if status == 0 {
		status = a2h.StatusFor(e.Code)
	}
	if e.RetryAfterSec > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(e.RetryAfterSec))
	}
	writeJSON(w, status, e)
}

func (g *Gateway) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, g.Capabilities())
}

func (g *Gateway) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, jws.JWKS{Keys: []jws.JWK{g.key.PublicJWK()}})
}

type apiHandler func(w http.ResponseWriter, r *http.Request, agent string) *a2h.APIError

// api authenticates the caller (spec section 1.8.3) before calling h.
func (g *Gateway) api(h apiHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent := "anonymous"
		key := r.Header.Get(a2h.HeaderAPIKey)
		if key == "" {
			key, _ = strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if name, ok := g.lookupKey(key); ok {
			agent = name
		} else if !g.cfg.NoAuth {
			writeError(w, a2h.Errorf(a2h.ErrUnauthorized, "missing or invalid API key"))
			return
		}
		if err := h(w, r, agent); err != nil {
			writeError(w, err)
		}
	}
}

func (g *Gateway) lookupKey(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	for k, name := range g.cfg.APIKeys {
		if hmac.Equal([]byte(k), []byte(key)) {
			return name, true
		}
	}
	return "", false
}

func (g *Gateway) allow(agent string) (bool, int) {
	g.rateMu.Lock()
	defer g.rateMu.Unlock()
	now := g.cfg.Now()
	win := g.rate[agent]
	if win == nil || now.Sub(win.start) >= time.Minute {
		win = &window{start: now}
		g.rate[agent] = win
	}
	if win.count >= g.cfg.RateLimitPerMinute {
		return false, int(time.Minute-now.Sub(win.start))/int(time.Second) + 1
	}
	win.count++
	return true, 0
}

func (g *Gateway) handleIntent(w http.ResponseWriter, r *http.Request, agent string) *a2h.APIError {
	if ok, retry := g.allow(agent); !ok {
		e := a2h.Errorf(a2h.ErrRateLimited, "too many intents; retry later")
		e.RetryAfterSec = retry
		return e
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		return a2h.Errorf(a2h.ErrInvalidRequest, "request body too large or unreadable")
	}
	var m a2h.Message
	if err := json.Unmarshal(body, &m); err != nil {
		return a2h.Errorf(a2h.ErrInvalidRequest, "invalid JSON: %v", err)
	}
	if apiErr := m.Validate(g.limits()); apiErr != nil {
		return apiErr
	}
	now := g.cfg.Now()
	ctx := r.Context()

	// Idempotency on message_id (spec section 1.10.2), checked before the
	// timestamp so that a retried request gets its original answer.
	if dup, err := g.duplicate(ctx, agent, m.MessageID, now); err != nil {
		return internal(g.log, err)
	} else if dup != nil {
		writeJSON(w, http.StatusOK, dup)
		return nil
	}
	if m.CreatedAt != "" {
		created, _ := time.Parse(time.RFC3339, m.CreatedAt)
		if d := now.Sub(created); d > g.cfg.TimestampTolerance || d < -g.cfg.TimestampTolerance {
			return a2h.Errorf(a2h.ErrReplayRejected, "created_at is more than %s away from the gateway's clock", g.cfg.TimestampTolerance)
		}
	}
	if m.Channel.Nonce != "" {
		res, err := g.store.db.ExecContext(ctx, `UPDATE nonces SET used = 1 WHERE nonce = ? AND used = 0 AND expires_at >= ?`, m.Channel.Nonce, ms(now))
		if err != nil {
			return internal(g.log, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return a2h.Errorf(a2h.ErrReplayRejected, "nonce is unknown, expired or already used")
		}
	}

	id := m.InteractionID
	parentID := ""
	if id != "" {
		parent, err := g.store.getInteraction(ctx, "id = ?", id)
		switch {
		case errors.Is(err, errNotFound):
			// A new interaction with an ID chosen by the agent.
		case err != nil:
			return internal(g.log, err)
		case parent.Agent != agent:
			return a2h.Errorf(a2h.ErrConflict, "interaction_id %q belongs to another caller", id)
		case a2h.ExpectsInput(m.Type):
			return a2h.Errorf(a2h.ErrConflict, "interaction %q already exists; start a new interaction to ask again", id)
		default:
			// A follow-up (RESULT, INFORM, ESCALATE) in an existing interaction.
			parentID = id
		}
	}
	rowID := id
	if rowID == "" || parentID != "" {
		rowID = a2h.NewID()
	}
	if id == "" {
		id = rowID
	}
	m.InteractionID = id
	stored, _ := json.Marshal(m)
	in := &interaction{
		ID: rowID, MessageID: m.MessageID, Agent: agent, Type: m.Type, State: a2h.StatePending, PrincipalID: m.PrincipalID,
		Request: stored, TokenHash: hashToken(g.linkToken(rowID)), CreatedAt: now, UpdatedAt: now, ParentID: parentID,
	}
	tx, err := g.store.db.BeginTx(ctx, nil)
	if err != nil {
		return internal(g.log, err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO seen_messages (agent, message_id, interaction_id, seen_at) VALUES (?,?,?,?) ON CONFLICT DO NOTHING`, agent, m.MessageID, rowID, ms(now))
	if err != nil {
		return internal(g.log, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Lost a race with an identical request.
		tx.Rollback()
		dup, err := g.duplicate(ctx, agent, m.MessageID, now)
		if err != nil || dup == nil {
			return internal(g.log, fmt.Errorf("duplicate lookup: %v", err))
		}
		writeJSON(w, http.StatusOK, dup)
		return nil
	}
	if err := g.store.insertInteraction(ctx, tx, in); err != nil {
		return internal(g.log, err)
	}
	if err := g.store.addJob(ctx, tx, job{Kind: "deliver", InteractionID: rowID, Attempt: 1, RunAt: now}); err != nil {
		return internal(g.log, err)
	}
	if err := tx.Commit(); err != nil {
		return internal(g.log, err)
	}
	g.log.Info("intent accepted", "interaction", id, "type", m.Type, "agent", agent, "channel", m.Channel.Type)
	writeJSON(w, http.StatusOK, a2h.IntentResponse{
		InteractionID: id, State: a2h.StatePending, CreatedAt: now.UTC().Format(time.RFC3339), TTLSec: m.TTLSec, ChannelID: m.Channel.Type,
	})
	return nil
}

// duplicate returns the original answer for a message_id seen in the window.
func (g *Gateway) duplicate(ctx context.Context, agent, messageID string, now time.Time) (*a2h.IntentResponse, error) {
	var rowID string
	err := g.store.db.QueryRowContext(ctx, `SELECT interaction_id FROM seen_messages WHERE agent = ? AND message_id = ? AND seen_at >= ?`,
		agent, messageID, ms(now.Add(-g.cfg.IdempotencyWindow))).Scan(&rowID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	in, err := g.store.getInteraction(ctx, "id = ?", rowID)
	if err != nil {
		return nil, err
	}
	in = g.refresh(ctx, in)
	var m a2h.Message
	json.Unmarshal(in.Request, &m)
	return &a2h.IntentResponse{
		InteractionID: m.InteractionID, State: in.State, CreatedAt: in.CreatedAt.Format(time.RFC3339), TTLSec: m.TTLSec, ChannelID: m.Channel.Type, Duplicate: true,
	}, nil
}

func internal(log *slog.Logger, err error) *a2h.APIError {
	log.Error("internal error", "err", err)
	e := a2h.Errorf("ERR.INTERNAL", "internal error")
	e.HTTPStatus = http.StatusInternalServerError
	return e
}

// refresh expires an interaction whose TTL elapsed, so that reads are
// correct even if the background sweep has not run yet.
func (g *Gateway) refresh(ctx context.Context, in *interaction) *interaction {
	now := g.cfg.Now()
	if in.State == a2h.StateWaitingInput && !in.ExpiresAt.IsZero() && !now.Before(in.ExpiresAt) {
		if g.expire(ctx, in.ID, now) {
			if fresh, err := g.store.getInteraction(ctx, "id = ?", in.ID); err == nil {
				return fresh
			}
		}
	}
	return in
}

func (g *Gateway) handleStatus(w http.ResponseWriter, r *http.Request, agent string) *a2h.APIError {
	in, err := g.store.getInteraction(r.Context(), "id = ?", r.PathValue("id"))
	if errors.Is(err, errNotFound) || (err == nil && in.Agent != agent) {
		return a2h.Errorf(a2h.ErrNotFound, "interaction not found")
	}
	if err != nil {
		return internal(g.log, err)
	}
	in = g.refresh(r.Context(), in)
	writeJSON(w, http.StatusOK, g.status(in))
	return nil
}

func (g *Gateway) status(in *interaction) a2h.InteractionStatus {
	s := a2h.InteractionStatus{
		InteractionID: in.ID, Type: in.Type, State: in.State,
		CreatedAt: in.CreatedAt.Format(time.RFC3339), UpdatedAt: in.UpdatedAt.Format(time.RFC3339),
		ChannelID: in.ChannelUsed, WebhookFailed: in.WebhookFailed,
	}
	if !in.ExpiresAt.IsZero() {
		s.ExpiresAt = in.ExpiresAt.Format(time.RFC3339)
	}
	if len(in.Response) > 0 {
		s.Response = json.RawMessage(in.Response)
	}
	if in.ErrorCode != "" {
		s.Error = &a2h.ErrorInfo{Code: in.ErrorCode, Message: in.ErrorMessage, Timestamp: in.UpdatedAt.Format(time.RFC3339)}
	}
	return s
}

func (g *Gateway) handleCancel(w http.ResponseWriter, r *http.Request, agent string) *a2h.APIError {
	ctx := r.Context()
	in, err := g.store.getInteraction(ctx, "id = ?", r.PathValue("id"))
	if errors.Is(err, errNotFound) || (err == nil && in.Agent != agent) {
		return a2h.Errorf(a2h.ErrNotFound, "interaction not found")
	}
	if err != nil {
		return internal(g.log, err)
	}
	in = g.refresh(ctx, in)
	// Messages that expect no answer can only be cancelled before delivery.
	cancellable := []any{a2h.StatePending, a2h.StatePending, a2h.StatePending}
	if a2h.ExpectsInput(in.Type) {
		cancellable = []any{a2h.StatePending, a2h.StateSent, a2h.StateWaitingInput}
	}
	now := g.cfg.Now()
	res, err := g.store.db.ExecContext(ctx, `UPDATE interactions SET state = ?, updated_at = ? WHERE id = ? AND state IN (?, ?, ?)`,
		append([]any{a2h.StateCancelled, ms(now), in.ID}, cancellable...)...)
	if err != nil {
		return internal(g.log, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return a2h.Errorf(a2h.ErrConflict, "interaction is already %s", strings.ToLower(in.State))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Interaction cancelled", "state": a2h.StateCancelled})
	return nil
}

func (g *Gateway) handleNonce(w http.ResponseWriter, r *http.Request, agent string) *a2h.APIError {
	n := randomToken()
	exp := g.cfg.Now().Add(5 * time.Minute)
	if _, err := g.store.db.ExecContext(r.Context(), `INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)`, n, ms(exp)); err != nil {
		return internal(g.log, err)
	}
	writeJSON(w, http.StatusOK, a2h.Nonce{Nonce: n, ExpiresAt: exp.UTC().Format(time.RFC3339)})
	return nil
}
