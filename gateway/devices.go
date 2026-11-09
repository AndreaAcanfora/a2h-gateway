package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/AndreaAcanfora/a2h-gateway/channels"
	"github.com/AndreaAcanfora/a2h-gateway/jws"
)

// The app channel delivers requests to a phone app paired with the gateway
// (such as nod, https://github.com/AndreaAcanfora/nod). The app holds a P-256
// key created on the phone; it signs every answer, and the RESPONSE carries
// that signature as evidence. docs/app-api.md describes the API.

// AppChannel is the channel type of paired apps. Addresses are app:<principal_id>.
const AppChannel = "app"

// DeviceAnswerType is the "typ" header of the JWS an app signs to answer.
const DeviceAnswerType = "a2h-device-answer+jws"

// Device is a phone app paired with the gateway.
type Device struct {
	ID          string    `json:"device_id"`
	PrincipalID string    `json:"principal_id"`
	Name        string    `json:"name"`
	PublicKey   jws.JWK   `json:"public_key"`
	Push        bool      `json:"push"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	pushURL     string
}

// CreatePairing returns a single-use link that pairs an app with a
// principal. Like passkey enrollment, only the operator may create these.
func (g *Gateway) CreatePairing(ctx context.Context, principal string, ttl time.Duration) (string, error) {
	if principal == "" || len(principal) > 256 {
		return "", errors.New("invalid principal ID")
	}
	token := randomToken()
	_, err := g.store.db.ExecContext(ctx, `INSERT INTO pairings (token_hash, principal_id, expires_at) VALUES (?,?,?)`, hashToken(token), principal, ms(g.cfg.Now().Add(ttl)))
	if err != nil {
		return "", err
	}
	return g.cfg.BaseURL + "/pair/" + token, nil
}

// Devices lists the paired devices, of one principal or of all when principal is empty.
func (g *Gateway) Devices(ctx context.Context, principal string) ([]Device, error) {
	q, args := `SELECT `+deviceCols+` FROM devices ORDER BY created_at`, []any{}
	if principal != "" {
		q, args = `SELECT `+deviceCols+` FROM devices WHERE principal_id = ? ORDER BY created_at`, []any{principal}
	}
	rows, err := g.store.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// RevokeDevice unpairs a device. It reports whether the device existed.
func (g *Gateway) RevokeDevice(ctx context.Context, id string) (bool, error) {
	res, err := g.store.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

const deviceCols = `id, principal_id, name, public_key, push_url, created_at, last_seen_at`

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	var key string
	var created, seen int64
	if err := row.Scan(&d.ID, &d.PrincipalID, &d.Name, &key, &d.pushURL, &created, &seen); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(key), &d.PublicKey); err != nil {
		return nil, err
	}
	d.Push = d.pushURL != ""
	d.CreatedAt, d.LastSeenAt = fromMS(created), fromMS(seen)
	return &d, nil
}

// deliverApp wakes the principal's paired apps. The push carries no content:
// the app fetches the request from the gateway, so push services never see it.
func (g *Gateway) deliverApp(ctx context.Context, m *a2h.Message, t target) error {
	principal, _ := strings.CutPrefix(t.Address, AppChannel+":")
	if principal != m.PrincipalID {
		return channels.Permanent(fmt.Errorf("app: address %q does not match principal_id %q", t.Address, m.PrincipalID))
	}
	devices, err := g.Devices(ctx, principal)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return channels.Permanent(fmt.Errorf("app: no app is paired for %q", principal))
	}
	payload, _ := json.Marshal(map[string]string{"a2h": "interaction", "interaction_id": m.InteractionID, "type": m.Type})
	polled := false
	var lastErr error
	for _, d := range devices {
		if d.pushURL == "" {
			// This app checks the gateway when it opens: nothing to wake.
			polled = true
			continue
		}
		if lastErr = g.push(ctx, d.pushURL, payload); lastErr == nil {
			polled = true
		} else {
			g.log.Warn("app push failed", "device", d.ID, "err", lastErr)
		}
	}
	if polled {
		return nil
	}
	return lastErr
}

// push POSTs to a UnifiedPush endpoint (for example an ntfy topic).
func (g *Gateway) push(ctx context.Context, endpoint string, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return channels.Permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("TTL", "86400")
	req.Header.Set("Urgency", "high")
	resp, err := g.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("push endpoint responded %d", resp.StatusCode)
	}
	return nil
}

func (g *Gateway) validPushURL(raw string) bool {
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || len(raw) > 2048 {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && g.cfg.InsecureWebhooks)
}

// deviceAPI authenticates an app by its device token.
func (g *Gateway) deviceAPI(h func(w http.ResponseWriter, r *http.Request, d *Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			writeJSON(w, http.StatusUnauthorized, deviceError("unauthorized", "missing device token"))
			return
		}
		d, err := scanDevice(g.store.db.QueryRowContext(r.Context(), `SELECT `+deviceCols+` FROM devices WHERE token_hash = ?`, hashToken(token)))
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusUnauthorized, deviceError("unpaired", "this device is not paired with the gateway (any more)"))
			return
		}
		if err != nil {
			g.log.Error("device lookup", "err", err)
			writeJSON(w, http.StatusInternalServerError, deviceError("internal", "internal error"))
			return
		}
		now := g.cfg.Now()
		if now.Sub(d.LastSeenAt) > time.Minute {
			g.store.db.ExecContext(r.Context(), `UPDATE devices SET last_seen_at = ? WHERE id = ?`, ms(now), d.ID)
		}
		h(w, r, d)
	}
}

func deviceError(code, message string) map[string]string {
	return map[string]string{"error": code, "message": message}
}

type pairRequest struct {
	Token     string  `json:"pairing_token"`
	Name      string  `json:"name"`
	PublicKey jws.JWK `json:"public_key"`
	PushURL   string  `json:"push_url,omitempty"`
}

func (g *Gateway) handlePair(w http.ResponseWriter, r *http.Request) {
	var req pairRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, deviceError("invalid_request", "invalid JSON"))
		return
	}
	pub, err := req.PublicKey.PublicKey()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, deviceError("invalid_request", "public_key must be a P-256 JWK"))
		return
	}
	if !g.validPushURL(req.PushURL) {
		writeJSON(w, http.StatusBadRequest, deviceError("invalid_request", "push_url must be an https URL"))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Phone"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	ctx := r.Context()
	now := g.cfg.Now()
	tx, err := g.store.db.BeginTx(ctx, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, deviceError("internal", "internal error"))
		return
	}
	defer tx.Rollback()
	var principal string
	err = tx.QueryRowContext(ctx, `UPDATE pairings SET used = 1 WHERE token_hash = ? AND used = 0 AND expires_at > ? RETURNING principal_id`, hashToken(req.Token), ms(now)).Scan(&principal)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusGone, deviceError("pairing_invalid", "This pairing link is unknown, expired or already used. Ask the gateway operator for a new one."))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, deviceError("internal", "internal error"))
		return
	}
	jwk := req.PublicKey
	jwk.Kid = jws.Thumbprint(pub)
	jwk.Alg, jwk.Use = "ES256", "sig"
	key, _ := json.Marshal(jwk)
	id := "dev_" + jwk.Kid[:22]
	token := randomToken()
	_, err = tx.ExecContext(ctx, `INSERT INTO devices (id, principal_id, name, public_key, token_hash, push_url, created_at, last_seen_at) VALUES (?,?,?,?,?,?,?,?)`,
		id, principal, name, string(key), hashToken(token), req.PushURL, ms(now), ms(now))
	if err != nil {
		writeJSON(w, http.StatusConflict, deviceError("conflict", "this key is already paired; create a new key"))
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, deviceError("internal", "internal error"))
		return
	}
	g.log.Info("app paired", "principal", principal, "device", id, "name", name)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": id, "device_token": token, "principal_id": principal,
		"gateway": map[string]any{"base_url": g.cfg.BaseURL, "jwks_uri": g.cfg.BaseURL + "/.well-known/jwks.json"},
	})
}

func (g *Gateway) handleDevice(w http.ResponseWriter, r *http.Request, d *Device) {
	writeJSON(w, http.StatusOK, d)
}

func (g *Gateway) handleDeviceUpdate(w http.ResponseWriter, r *http.Request, d *Device) {
	var req struct {
		Name    *string `json:"name"`
		PushURL *string `json:"push_url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, deviceError("invalid_request", "invalid JSON"))
		return
	}
	if req.PushURL != nil {
		if !g.validPushURL(*req.PushURL) {
			writeJSON(w, http.StatusBadRequest, deviceError("invalid_request", "push_url must be an https URL"))
			return
		}
		g.store.db.ExecContext(r.Context(), `UPDATE devices SET push_url = ? WHERE id = ?`, *req.PushURL, d.ID)
		d.pushURL, d.Push = *req.PushURL, *req.PushURL != ""
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) != "" && len(*req.Name) <= 64 {
		d.Name = strings.TrimSpace(*req.Name)
		g.store.db.ExecContext(r.Context(), `UPDATE devices SET name = ? WHERE id = ?`, d.Name, d.ID)
	}
	writeJSON(w, http.StatusOK, d)
}

func (g *Gateway) handleUnpair(w http.ResponseWriter, r *http.Request, d *Device) {
	g.RevokeDevice(r.Context(), d.ID)
	g.log.Info("app unpaired itself", "device", d.ID)
	writeJSON(w, http.StatusOK, map[string]string{"result": "unpaired"})
}

// InboxItem is one request as an app shows it.
type InboxItem struct {
	InteractionID string          `json:"interaction_id"`
	Type          string          `json:"type"`
	State         string          `json:"state"`
	AgentID       string          `json:"agent_id"`
	Title         string          `json:"title,omitempty"`
	Body          string          `json:"body"`
	Footer        string          `json:"footer,omitempty"`
	Why           string          `json:"why,omitempty"`
	Components    []a2h.Component `json:"components,omitempty"`
	CreatedAt     string          `json:"created_at"`
	ExpiresAt     string          `json:"expires_at,omitempty"`
	// RequiredFactor is set when an approval needs a factor the app does not
	// have (a passkey): the app then sends the person to WebURL.
	RequiredFactor string `json:"required_factor,omitempty"`
	WebURL         string `json:"web_url,omitempty"`
	Decision       string `json:"decision,omitempty"`
	DecidedAt      string `json:"decided_at,omitempty"`
	Factor         string `json:"factor,omitempty"`
	Data           any    `json:"data,omitempty"`
	Error          string `json:"error,omitempty"`
}

func (g *Gateway) inboxItem(in *interaction) (InboxItem, error) {
	var m a2h.Message
	if err := json.Unmarshal(in.Request, &m); err != nil {
		return InboxItem{}, err
	}
	rd := m.EffectiveRender()
	it := InboxItem{
		InteractionID: m.InteractionID, Type: in.Type, State: in.State, AgentID: m.AgentID,
		Title: rd.Title, Body: rd.Body, Footer: rd.Footer, Components: m.Components,
		CreatedAt: in.CreatedAt.Format(time.RFC3339), Error: in.ErrorMessage,
	}
	if in.ParentID != "" {
		it.InteractionID = in.ID // follow-ups have their own row
	}
	if why, ok := m.ExplanationBundle["why"].(string); ok {
		it.Why = why
	}
	if !in.ExpiresAt.IsZero() {
		it.ExpiresAt = in.ExpiresAt.Format(time.RFC3339)
	}
	if in.State == a2h.StateWaitingInput {
		if m.Type == a2h.Authorize && m.RequiresPasskey() {
			it.RequiredFactor = a2h.FactorPasskey
		}
		it.WebURL = g.cfg.BaseURL + "/i/" + g.linkToken(in.ID)
	}
	if len(in.Response) > 0 {
		var resp a2h.ResponseMessage
		if json.Unmarshal(in.Response, &resp) == nil {
			it.Decision, it.DecidedAt, it.Data = resp.Decision, resp.DecidedAt, resp.Data
			if resp.Evidence != nil {
				it.Factor = resp.Evidence.Factor
			}
		}
	}
	return it, nil
}

// handleInbox lists the requests waiting for the principal, then the most
// recent ones of the last week.
func (g *Gateway) handleInbox(w http.ResponseWriter, r *http.Request, d *Device) {
	ctx := r.Context()
	now := g.cfg.Now()
	rows, err := g.store.db.QueryContext(ctx, `SELECT `+interactionCols+` FROM interactions
		WHERE principal_id = ? AND state != ? AND (state = ? OR created_at > ?)
		ORDER BY CASE WHEN state = ? THEN 0 ELSE 1 END, created_at DESC LIMIT 100`,
		d.PrincipalID, a2h.StatePending, a2h.StateWaitingInput, ms(now.Add(-7*24*time.Hour)), a2h.StateWaitingInput)
	if err != nil {
		g.log.Error("inbox", "err", err)
		writeJSON(w, http.StatusInternalServerError, deviceError("internal", "internal error"))
		return
	}
	var ins []*interaction
	for rows.Next() {
		in, err := scanInteraction(rows)
		if err != nil {
			rows.Close()
			writeJSON(w, http.StatusInternalServerError, deviceError("internal", "internal error"))
			return
		}
		ins = append(ins, in)
	}
	rows.Close()
	items := []InboxItem{}
	for _, in := range ins {
		in = g.refresh(ctx, in)
		if it, err := g.inboxItem(in); err == nil {
			items = append(items, it)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"principal_id": d.PrincipalID, "server_time": now.UTC().Format(time.RFC3339), "items": items})
}

// DeviceAnswer is the payload of the JWS an app signs to answer a request.
type DeviceAnswer struct {
	InteractionID string         `json:"interaction_id"`
	Decision      string         `json:"decision"` // APPROVE, DECLINE or SUBMIT
	Data          map[string]any `json:"data,omitempty"`
	DeviceID      string         `json:"device_id"`
	IssuedAt      int64          `json:"iat"`
}

// handleDeviceAnswer records an answer signed by the app's key.
func (g *Gateway) handleDeviceAnswer(w http.ResponseWriter, r *http.Request, d *Device) {
	ctx := r.Context()
	var req struct {
		JWS string `json:"jws"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, deviceError("invalid_request", "invalid JSON"))
		return
	}
	pub, err := d.PublicKey.PublicKey()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, deviceError("internal", "internal error"))
		return
	}
	hdr, payload, err := jws.VerifyCompact(req.JWS, pub)
	if err != nil {
		g.log.Warn("app answer rejected", "device", d.ID, "err", err)
		writeJSON(w, http.StatusUnauthorized, deviceError("bad_signature", "the answer is not signed by this device's key"))
		return
	}
	var h struct {
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	var a DeviceAnswer
	if json.Unmarshal(hdr, &h) != nil || h.Typ != DeviceAnswerType || h.Kid != d.PublicKey.Kid || json.Unmarshal(payload, &a) != nil || a.DeviceID != d.ID {
		writeJSON(w, http.StatusBadRequest, deviceError("invalid_request", "the signed answer does not belong to this device"))
		return
	}
	now := g.cfg.Now()
	if skew := now.Sub(time.Unix(a.IssuedAt, 0)); skew > g.cfg.TimestampTolerance || skew < -g.cfg.TimestampTolerance {
		writeJSON(w, http.StatusBadRequest, deviceError("clock_skew", "the answer's time is too far from the gateway's clock; check the phone's clock"))
		return
	}
	in, err := g.store.getInteraction(ctx, "id = ?", a.InteractionID)
	if err != nil || in.PrincipalID != d.PrincipalID {
		writeJSON(w, http.StatusNotFound, deviceError("not_found", "no such request"))
		return
	}
	in = g.refresh(ctx, in)
	if in.State != a2h.StateWaitingInput {
		it, _ := g.inboxItem(in)
		writeJSON(w, http.StatusGone, map[string]any{"error": "closed", "message": "This request is no longer waiting for an answer.", "item": it})
		return
	}
	var m a2h.Message
	json.Unmarshal(in.Request, &m)
	decision, data := a.Decision, map[string]any(nil)
	switch {
	case decision == a2h.Decline:
	case m.Type == a2h.Authorize && decision == a2h.Approve:
		if m.RequiresPasskey() {
			writeJSON(w, http.StatusForbidden, deviceError("passkey_required", "This request must be approved with a passkey in the browser."))
			return
		}
	case m.Type == a2h.Collect && decision == "SUBMIT":
		var problems map[string]string
		data, problems = a2h.ValidateAnswer(m.Components, formValues(a.Data))
		if len(problems) > 0 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_data", "message": "Please check the highlighted fields.", "problems": problems})
			return
		}
		decision = ""
	default:
		writeJSON(w, http.StatusBadRequest, deviceError("invalid_request", "unknown decision for a "+m.Type))
		return
	}
	evidence := &a2h.Evidence{Factor: a2h.FactorDeviceKey, Proof: map[string]any{
		"jws":         req.JWS,
		"public_key":  d.PublicKey,
		"device_id":   d.ID,
		"device_name": d.Name,
		"verified_at": now.UTC().Format(time.RFC3339),
	}}
	if _, err := g.answer(ctx, in, decision, data, evidence); err != nil {
		in, _ = g.store.getInteraction(ctx, "id = ?", in.ID)
		it, _ := g.inboxItem(in)
		writeJSON(w, http.StatusGone, map[string]any{"error": "closed", "message": "This request is no longer waiting for an answer.", "item": it})
		return
	}
	in, _ = g.store.getInteraction(ctx, "id = ?", in.ID)
	it, _ := g.inboxItem(in)
	writeJSON(w, http.StatusOK, map[string]any{"result": "answered", "item": it})
}

// formValues turns JSON answer data into the form shape ValidateAnswer reads.
func formValues(data map[string]any) map[string][]string {
	out := map[string][]string{}
	for k, v := range data {
		switch v := v.(type) {
		case string:
			out[k] = []string{v}
		case bool:
			out[k] = []string{fmt.Sprint(v)}
		case float64:
			out[k] = []string{fmt.Sprint(v)}
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					out[k] = append(out[k], s)
				}
			}
		}
	}
	return out
}

// VerifyDeviceEvidence checks the evidence of an answer given in an app: the
// JWS verifies with the public key in the proof and answers this interaction.
// Agents can use it to check a RESPONSE without trusting the gateway's word
// alone (they must still check that the key belongs to the principal).
func VerifyDeviceEvidence(ev *a2h.Evidence, interactionID string) (*DeviceAnswer, error) {
	if ev == nil || ev.Factor != a2h.FactorDeviceKey {
		return nil, errors.New("not device evidence")
	}
	compact, _ := ev.Proof["jws"].(string)
	raw, _ := json.Marshal(ev.Proof["public_key"])
	var jwk jws.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, err
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return nil, err
	}
	_, payload, err := jws.VerifyCompact(compact, pub)
	if err != nil {
		return nil, err
	}
	var a DeviceAnswer
	if err := json.Unmarshal(payload, &a); err != nil {
		return nil, err
	}
	if a.InteractionID != interactionID {
		return nil, errors.New("evidence answers another interaction")
	}
	return &a, nil
}

func (g *Gateway) handlePairPage(w http.ResponseWriter, r *http.Request) {
	var principal string
	err := g.store.db.QueryRowContext(r.Context(), `SELECT principal_id FROM pairings WHERE token_hash = ? AND used = 0 AND expires_at > ?`,
		hashToken(r.PathValue("token")), ms(g.cfg.Now())).Scan(&principal)
	if err != nil {
		g.renderPage(w, http.StatusGone, pageData{Heading: "Link not valid", Notice: "This pairing link is unknown, expired or already used."})
		return
	}
	link := g.cfg.BaseURL + "/pair/" + r.PathValue("token")
	g.renderPage(w, http.StatusOK, pageData{Pair: true, Heading: "Pair your phone", Principal: principal, PairLink: link, PairQR: qrSVG(link)})
}
