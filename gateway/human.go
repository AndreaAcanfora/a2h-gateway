package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// principalUser adapts a principal to go-webauthn.
type principalUser struct {
	id     string
	handle []byte
	creds  []webauthn.Credential
}

func (u *principalUser) WebAuthnID() []byte                         { return u.handle }
func (u *principalUser) WebAuthnName() string                       { return u.id }
func (u *principalUser) WebAuthnDisplayName() string                { return u.id }
func (u *principalUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// loadPrincipal returns a principal and its passkeys; create makes it if missing.
func (g *Gateway) loadPrincipal(ctx context.Context, id string, create bool) (*principalUser, error) {
	u := &principalUser{id: id}
	err := g.store.db.QueryRowContext(ctx, `SELECT handle FROM principals WHERE id = ?`, id).Scan(&u.handle)
	if errors.Is(err, sql.ErrNoRows) {
		if !create {
			return u, nil
		}
		u.handle = make([]byte, 32)
		rand.Read(u.handle)
		if _, err := g.store.db.ExecContext(ctx, `INSERT INTO principals (id, handle, created_at) VALUES (?,?,?)`, id, u.handle, ms(g.cfg.Now())); err != nil {
			return nil, err
		}
		return u, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := g.store.db.QueryContext(ctx, `SELECT data FROM credentials WHERE principal_id = ? ORDER BY created_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		var c webauthn.Credential
		if rows.Scan(&data) == nil && json.Unmarshal([]byte(data), &c) == nil {
			u.creds = append(u.creds, c)
		}
	}
	return u, rows.Err()
}

func (g *Gateway) saveCredential(ctx context.Context, principal string, c *webauthn.Credential) error {
	data, _ := json.Marshal(c)
	_, err := g.store.db.ExecContext(ctx, `INSERT INTO credentials (id, principal_id, data, created_at) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET data = excluded.data`,
		c.ID, principal, string(data), ms(g.cfg.Now()))
	return err
}

// PasskeyCount returns how many passkeys a principal has enrolled.
func (g *Gateway) PasskeyCount(ctx context.Context, principal string) (int, error) {
	var n int
	err := g.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM credentials WHERE principal_id = ?`, principal).Scan(&n)
	return n, err
}

// lookupLink finds the interaction behind a link token.
func (g *Gateway) lookupLink(ctx context.Context, token string) (*interaction, *a2h.Message, error) {
	in, err := g.store.getInteraction(ctx, "token_hash = ?", hashToken(token))
	if err != nil {
		return nil, nil, err
	}
	in = g.refresh(ctx, in)
	var m a2h.Message
	if err := json.Unmarshal(in.Request, &m); err != nil {
		return nil, nil, err
	}
	return in, &m, nil
}

// sameOrigin rejects cross-site POSTs to the human pages.
func (g *Gateway) sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	return o == "" || o == g.origin
}

func (g *Gateway) handlePage(w http.ResponseWriter, r *http.Request) {
	in, m, err := g.lookupLink(r.Context(), r.PathValue("token"))
	if err != nil {
		g.renderPage(w, http.StatusNotFound, pageData{Heading: "Link not valid", Notice: "This link does not match any request. Check that you opened the whole link."})
		return
	}
	g.renderInteraction(w, r, in, m, "", nil)
}

func (g *Gateway) renderInteraction(w http.ResponseWriter, r *http.Request, in *interaction, m *a2h.Message, problem string, problems map[string]string) {
	g.renderInteractionStatus(w, r, in, m, problem, problems, false)
}

// renderInteractionStatus renders the page; justAnswered answers 200 instead
// of 410 to the request that recorded the answer.
func (g *Gateway) renderInteractionStatus(w http.ResponseWriter, r *http.Request, in *interaction, m *a2h.Message, problem string, problems map[string]string, justAnswered bool) {
	rd := m.EffectiveRender()
	d := pageData{
		Token: r.PathValue("token"), Intent: m.Type, Heading: rd.Title, Body: rd.Body, Footer: rd.Footer,
		Agent: m.AgentID, Components: m.Components, Problem: problem, Problems: problems, Values: r.PostForm,
	}
	if d.Heading == "" {
		d.Heading = map[string]string{a2h.Authorize: "Approval needed", a2h.Collect: "Information needed", a2h.Escalate: "Continue elsewhere"}[m.Type]
		if d.Heading == "" {
			d.Heading = "Message from your agent"
		}
	}
	if why, ok := m.ExplanationBundle["why"].(string); ok {
		d.Why = why
	}
	if targets, ok := m.Params["targets"].([]any); ok {
		for _, t := range targets {
			if s, ok := t.(string); ok {
				d.Targets = append(d.Targets, escalationLink(s))
			}
		}
	}
	status := http.StatusOK
	switch in.State {
	case a2h.StateWaitingInput:
		d.Open = true
		if !in.ExpiresAt.IsZero() {
			d.Expires = in.ExpiresAt.Format(time.RFC3339)
		}
		if m.Type == a2h.Authorize && m.RequiresPasskey() {
			d.Passkey = true
			n, _ := g.PasskeyCount(r.Context(), m.PrincipalID)
			d.NoPasskey = n == 0
		}
	case a2h.StateSent:
		// INFORM, RESULT, ESCALATE: nothing to answer.
	case a2h.StateAnswered:
		status = http.StatusGone
		if justAnswered {
			status = http.StatusOK
		}
		var resp a2h.ResponseMessage
		json.Unmarshal(in.Response, &resp)
		d.Notice = "You already answered this request."
		switch resp.Decision {
		case a2h.Approve:
			d.Notice = "You approved this request. The agent has been told."
		case a2h.Decline:
			d.Notice = "You declined this request. The agent has been told."
		}
		d.Done = true
	case a2h.StateExpired:
		status = http.StatusGone
		d.Notice = "This request expired before an answer was given. The agent has been told."
	case a2h.StateCancelled:
		status = http.StatusGone
		d.Notice = "The agent cancelled this request. Nothing more to do."
	case a2h.StateFailed:
		status = http.StatusGone
		d.Notice = "This request is no longer active."
	default:
		d.Notice = "This request is being delivered. Reload in a moment."
	}
	if problem != "" || len(problems) > 0 {
		status = http.StatusUnprocessableEntity
	}
	g.renderPage(w, status, d)
}

type link struct{ Label, URL string }

func escalationLink(target string) link {
	kind, rest, _ := strings.Cut(target, ":")
	switch kind {
	case "voice":
		return link{"Call " + strings.TrimPrefix(rest, "tel:"), rest}
	case "chat", "web":
		if strings.HasPrefix(rest, "https://") {
			return link{"Open chat", rest}
		}
	}
	return link{target, ""}
}

func (g *Gateway) handleAnswer(w http.ResponseWriter, r *http.Request) {
	if !g.sameOrigin(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	in, m, err := g.lookupLink(ctx, r.PathValue("token"))
	if err != nil {
		g.renderPage(w, http.StatusNotFound, pageData{Heading: "Link not valid", Notice: "This link does not match any request."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if in.State != a2h.StateWaitingInput {
		g.renderInteraction(w, r, in, m, "", nil)
		return
	}
	decision := r.PostForm.Get("decision")
	var data map[string]any
	switch {
	case decision == a2h.Decline:
		// Declining never needs a strong factor.
	case m.Type == a2h.Authorize && decision == a2h.Approve:
		if m.RequiresPasskey() {
			g.renderInteraction(w, r, in, m, "This request must be approved with a passkey.", nil)
			return
		}
	case m.Type == a2h.Collect && decision == "SUBMIT":
		var problems map[string]string
		data, problems = a2h.ValidateAnswer(m.Components, r.PostForm)
		if len(problems) > 0 {
			g.renderInteraction(w, r, in, m, "Please check the highlighted fields.", problems)
			return
		}
		decision = "" // a COLLECT answer carries data, not a decision
	default:
		http.Error(w, "unknown decision", http.StatusBadRequest)
		return
	}
	_, err = g.answer(ctx, in, decision, data, g.linkEvidence(in, m))
	if err != nil && !errors.Is(err, errAlreadyHandled) {
		g.log.Error("answer", "err", err)
	}
	in, m, _ = g.lookupLink(ctx, r.PathValue("token"))
	g.renderInteractionStatus(w, r, in, m, "", nil, err == nil)
}

// linkEvidence is the gateway's attestation that the answer came through the
// secret link delivered on a channel (no cryptographic proof from the human).
func (g *Gateway) linkEvidence(in *interaction, m *a2h.Message) *a2h.Evidence {
	factor, address := a2h.FactorLink, ""
	for _, t := range targets(m) {
		if t.Type == in.ChannelUsed {
			address = t.Address
			break
		}
	}
	if in.ChannelUsed == "email" {
		factor = a2h.FactorEmailLink
	}
	return &a2h.Evidence{Factor: factor, Proof: map[string]any{
		"verified_at":      g.cfg.Now().UTC().Format(time.RFC3339),
		"delivery_channel": address,
		"channel_type":     in.ChannelUsed,
	}}
}

type assertSession struct {
	Session webauthn.SessionData `json:"session"`
	Nonce   string               `json:"nonce"`
}

// passkeyChallenge binds a WebAuthn challenge to an interaction, as spec
// section 1.11.4 requires: sha256(interaction_id + nonce).
func passkeyChallenge(interactionID, nonce string) []byte {
	sum := sha256.Sum256([]byte(interactionID + nonce))
	return sum[:]
}

func (g *Gateway) handlePasskeyOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !g.sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
		return
	}
	in, m, err := g.lookupLink(ctx, r.PathValue("token"))
	if err != nil || in.State != a2h.StateWaitingInput || m.Type != a2h.Authorize {
		writeJSON(w, http.StatusGone, map[string]string{"error": "This request is no longer waiting for an answer."})
		return
	}
	user, err := g.loadPrincipal(ctx, m.PrincipalID, false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if len(user.creds) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "No passkey is enrolled for you yet. Ask the gateway operator for an enrollment link."})
		return
	}
	nonce := randomToken()
	options, session, err := g.webauthn.BeginLogin(user,
		webauthn.WithChallenge(passkeyChallenge(m.InteractionID, nonce)),
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		g.log.Error("begin login", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	data, _ := json.Marshal(assertSession{Session: *session, Nonce: nonce})
	g.store.putSession(ctx, "assert:"+in.ID, data, g.cfg.Now().Add(5*time.Minute))
	writeJSON(w, http.StatusOK, options)
}

func (g *Gateway) handlePasskeyVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !g.sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
		return
	}
	in, m, err := g.lookupLink(ctx, r.PathValue("token"))
	if err != nil || in.State != a2h.StateWaitingInput {
		writeJSON(w, http.StatusGone, map[string]string{"error": "This request is no longer waiting for an answer."})
		return
	}
	raw, err := g.store.takeSession(ctx, "assert:"+in.ID, g.cfg.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The passkey prompt expired. Try again."})
		return
	}
	var s assertSession
	json.Unmarshal(raw, &s)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid passkey response"})
		return
	}
	user, err := g.loadPrincipal(ctx, m.PrincipalID, false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	cred, err := g.webauthn.ValidateLogin(user, s.Session, parsed)
	if err != nil {
		g.log.Warn("passkey rejected", "interaction", in.ID, "err", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "The passkey could not be verified."})
		return
	}
	g.saveCredential(ctx, m.PrincipalID, cred) // new signature counter
	b64 := base64.RawURLEncoding.EncodeToString
	a := parsed.Raw.AssertionResponse
	evidence := &a2h.Evidence{Factor: a2h.FactorPasskey, Proof: map[string]any{
		"credentialId":      b64(parsed.RawID),
		"clientDataJSON":    b64(a.ClientDataJSON),
		"authenticatorData": b64(a.AuthenticatorData),
		"signature":         b64(a.Signature),
		"userHandle":        b64(a.UserHandle),
		// challenge = base64url(sha256(interaction_id + challenge_nonce))
		"challenge_nonce": s.Nonce,
		"publicKey":       b64(cred.PublicKey),
	}}
	if _, err := g.answer(ctx, in, a2h.Approve, nil, evidence); err != nil {
		writeJSON(w, http.StatusGone, map[string]string{"error": "This request is no longer waiting for an answer."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "approved"})
}

// CreateEnrollment returns a single-use link where a principal registers a
// passkey. Only the operator should create these: an agent able to enroll
// passkeys could approve its own requests.
func (g *Gateway) CreateEnrollment(ctx context.Context, principal string, ttl time.Duration) (string, error) {
	if principal == "" || len(principal) > 256 {
		return "", errors.New("invalid principal ID")
	}
	if _, err := g.loadPrincipal(ctx, principal, true); err != nil {
		return "", err
	}
	token := randomToken()
	_, err := g.store.db.ExecContext(ctx, `INSERT INTO enrollments (token_hash, principal_id, expires_at) VALUES (?,?,?)`, hashToken(token), principal, ms(g.cfg.Now().Add(ttl)))
	if err != nil {
		return "", err
	}
	return g.cfg.BaseURL + "/enroll/" + token, nil
}

func (g *Gateway) enrollment(ctx context.Context, token string) (string, error) {
	var principal string
	err := g.store.db.QueryRowContext(ctx, `SELECT principal_id FROM enrollments WHERE token_hash = ? AND used = 0 AND expires_at > ?`, hashToken(token), ms(g.cfg.Now())).Scan(&principal)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errNotFound
	}
	return principal, err
}

func (g *Gateway) handleEnrollPage(w http.ResponseWriter, r *http.Request) {
	principal, err := g.enrollment(r.Context(), r.PathValue("token"))
	if err != nil {
		g.renderPage(w, http.StatusGone, pageData{Heading: "Link not valid", Notice: "This enrollment link is unknown, expired or already used."})
		return
	}
	n, _ := g.PasskeyCount(r.Context(), principal)
	g.renderPage(w, http.StatusOK, pageData{Enroll: true, Token: r.PathValue("token"), Heading: "Create a passkey", Principal: principal, PasskeyCount: n})
}

func (g *Gateway) handleEnrollOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !g.sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
		return
	}
	token := r.PathValue("token")
	principal, err := g.enrollment(ctx, token)
	if err != nil {
		writeJSON(w, http.StatusGone, map[string]string{"error": "This enrollment link is no longer valid."})
		return
	}
	user, err := g.loadPrincipal(ctx, principal, true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range user.creds {
		exclude = append(exclude, c.Descriptor())
	}
	options, session, err := g.webauthn.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithExclusions(exclude))
	if err != nil {
		g.log.Error("begin registration", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	data, _ := json.Marshal(session)
	g.store.putSession(ctx, "enroll:"+hashToken(token), data, g.cfg.Now().Add(5*time.Minute))
	writeJSON(w, http.StatusOK, options)
}

func (g *Gateway) handleEnrollVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !g.sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
		return
	}
	token := r.PathValue("token")
	principal, err := g.enrollment(ctx, token)
	if err != nil {
		writeJSON(w, http.StatusGone, map[string]string{"error": "This enrollment link is no longer valid."})
		return
	}
	raw, err := g.store.takeSession(ctx, "enroll:"+hashToken(token), g.cfg.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The passkey prompt expired. Try again."})
		return
	}
	var session webauthn.SessionData
	json.Unmarshal(raw, &session)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid passkey response"})
		return
	}
	user, err := g.loadPrincipal(ctx, principal, true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	cred, err := g.webauthn.CreateCredential(user, session, parsed)
	if err != nil {
		g.log.Warn("passkey registration rejected", "principal", principal, "err", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The passkey could not be registered."})
		return
	}
	res, err := g.store.db.ExecContext(ctx, `UPDATE enrollments SET used = 1 WHERE token_hash = ? AND used = 0`, hashToken(token))
	if n, _ := res.RowsAffected(); err != nil || n != 1 {
		writeJSON(w, http.StatusGone, map[string]string{"error": "This enrollment link was already used."})
		return
	}
	if err := g.saveCredential(ctx, principal, cred); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	g.log.Info("passkey enrolled", "principal", principal)
	writeJSON(w, http.StatusOK, map[string]string{"result": "enrolled"})
}
