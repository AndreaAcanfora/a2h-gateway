package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/AndreaAcanfora/a2h-gateway/channels"
)

// Run processes deliveries, webhooks and expirations until ctx ends.
func (g *Gateway) Run(ctx context.Context) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	lastCleanup := time.Time{}
	for {
		g.Tick(ctx)
		if now := g.cfg.Now(); now.Sub(lastCleanup) > time.Minute {
			if err := g.store.cleanup(ctx, now, g.cfg.IdempotencyWindow); err != nil && ctx.Err() == nil {
				g.log.Error("cleanup", "err", err)
			}
			lastCleanup = now
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Tick runs the work that is due now: expirations, then jobs. Tests call it
// directly instead of Run.
func (g *Gateway) Tick(ctx context.Context) {
	now := g.cfg.Now()
	rows, err := g.store.db.QueryContext(ctx, `SELECT id FROM interactions WHERE state = ? AND expires_at > 0 AND expires_at <= ?`, a2h.StateWaitingInput, ms(now))
	if err == nil {
		var ids []string
		for rows.Next() {
			var id string
			rows.Scan(&id)
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			g.expire(ctx, id, now)
		}
	}
	jobs, err := g.store.takeDueJobs(ctx, now, 50)
	if err != nil {
		if ctx.Err() == nil {
			g.log.Error("taking jobs", "err", err)
		}
		return
	}
	for _, j := range jobs {
		switch j.Kind {
		case "deliver":
			g.deliver(ctx, j)
		case "webhook":
			g.sendWebhook(ctx, j)
		}
	}
}

// expire moves an interaction whose TTL elapsed to EXPIRED and notifies the
// agent. It reports whether it changed anything.
func (g *Gateway) expire(ctx context.Context, id string, now time.Time) bool {
	res, err := g.store.db.ExecContext(ctx, `UPDATE interactions SET state = ?, updated_at = ?, error_code = ?, error_message = ? WHERE id = ? AND state = ? AND expires_at <= ?`,
		a2h.StateExpired, ms(now), a2h.ErrExpired, "Request expired before response received", id, a2h.StateWaitingInput, ms(now))
	if err != nil {
		g.log.Error("expire", "err", err)
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false
	}
	g.log.Info("interaction expired", "interaction", id)
	g.notifyError(ctx, id, a2h.ErrExpired, "Request expired before response received")
	return true
}

type target struct{ Type, Address string }

func targets(m *a2h.Message) []target {
	t := []target{{m.Channel.Type, m.Channel.Address}}
	for _, f := range m.Channel.Fallback {
		t = append(t, target{f.Type, f.Address})
	}
	return t
}

func (g *Gateway) deliver(ctx context.Context, j job) {
	in, err := g.store.getInteraction(ctx, "id = ?", j.InteractionID)
	if err != nil {
		g.log.Error("deliver: load", "interaction", j.InteractionID, "err", err)
		return
	}
	if in.State != a2h.StatePending {
		return // cancelled meanwhile
	}
	var m a2h.Message
	if err := json.Unmarshal(in.Request, &m); err != nil {
		g.log.Error("deliver: decode", "err", err)
		return
	}
	ts := targets(&m)
	if j.ChannelIndex >= len(ts) {
		return
	}
	t := ts[j.ChannelIndex]
	now := g.cfg.Now()
	n := g.notification(in, &m, t, now)
	err = errors.New("channel not configured")
	if t.Type == AppChannel {
		err = g.deliverApp(ctx, &m, t)
	} else if ch, ok := g.channels[t.Type]; ok {
		dctx, cancel := context.WithTimeout(ctx, time.Minute)
		err = ch.Deliver(dctx, n)
		cancel()
	}
	if err == nil {
		g.delivered(ctx, in, &m, t, now)
		return
	}
	permanent := channels.IsPermanent(err) || (g.channels[t.Type] == nil && t.Type != AppChannel)
	g.log.Warn("delivery failed", "interaction", in.ID, "channel", t.Type, "attempt", j.Attempt, "permanent", permanent, "err", err)
	next := job{Kind: "deliver", InteractionID: in.ID}
	switch {
	case !permanent && j.Attempt < len(g.cfg.DeliveryRetry):
		next.ChannelIndex, next.Attempt, next.RunAt = j.ChannelIndex, j.Attempt+1, now.Add(g.cfg.DeliveryRetry[j.Attempt])
	case j.ChannelIndex+1 < len(ts):
		// Spec section 1.13.3: fall back once the primary's retries are exhausted.
		next.ChannelIndex, next.Attempt, next.RunAt = j.ChannelIndex+1, 1, now
	default:
		g.fail(ctx, in.ID, a2h.ErrDeliveryFailed, "All channels failed: "+err.Error())
		return
	}
	if err := g.store.addJob(ctx, g.store.db, next); err != nil {
		g.log.Error("deliver: reschedule", "err", err)
	}
}

func (g *Gateway) notification(in *interaction, m *a2h.Message, t target, now time.Time) channels.Notification {
	r := m.EffectiveRender()
	n := channels.Notification{
		InteractionID: m.InteractionID, Intent: m.Type, Title: r.Title, Body: r.Body,
		ActionURL: g.cfg.BaseURL + "/i/" + g.linkToken(in.ID), Address: t.Address,
	}
	if why, ok := m.ExplanationBundle["why"].(string); ok {
		n.Why = why
	}
	if a2h.ExpectsInput(m.Type) {
		n.ExpiresAt = now.Add(time.Duration(m.TTLSec) * time.Second)
	}
	return n
}

func (g *Gateway) delivered(ctx context.Context, in *interaction, m *a2h.Message, t target, now time.Time) {
	state, expires := a2h.StateSent, int64(0)
	if a2h.ExpectsInput(m.Type) {
		// SENT then, on the provider's acknowledgement, WAITING_INPUT: the
		// TTL starts now (spec section 1.6).
		state, expires = a2h.StateWaitingInput, ms(now.Add(time.Duration(m.TTLSec)*time.Second))
	}
	_, err := g.store.db.ExecContext(ctx, `UPDATE interactions SET state = ?, channel_used = ?, updated_at = ?, expires_at = ? WHERE id = ? AND state = ?`,
		state, t.Type, ms(now), expires, in.ID, a2h.StatePending)
	if err != nil {
		g.log.Error("deliver: update", "err", err)
		return
	}
	g.log.Info("delivered", "interaction", in.ID, "channel", t.Type, "state", state)
}

func (g *Gateway) fail(ctx context.Context, id, code, message string) {
	now := g.cfg.Now()
	res, err := g.store.db.ExecContext(ctx, `UPDATE interactions SET state = ?, updated_at = ?, error_code = ?, error_message = ? WHERE id = ? AND state IN (?, ?, ?)`,
		a2h.StateFailed, ms(now), code, message, id, a2h.StatePending, a2h.StateSent, a2h.StateWaitingInput)
	if err != nil {
		g.log.Error("fail", "err", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 1 {
		g.log.Warn("interaction failed", "interaction", id, "code", code)
		g.notifyError(ctx, id, code, message)
	}
}

// notifyError sends an A2H ERROR message to the agent's webhook, if any, so
// that agents that rely on webhooks learn that no answer will come.
func (g *Gateway) notifyError(ctx context.Context, id, code, message string) {
	in, err := g.store.getInteraction(ctx, "id = ?", id)
	if err != nil {
		return
	}
	var m a2h.Message
	json.Unmarshal(in.Request, &m)
	if m.Callback == nil {
		return
	}
	now := g.cfg.Now().UTC().Format(time.RFC3339)
	msg := a2h.ErrorMessage{
		A2HVersion: a2h.Version, Type: a2h.Error, MessageID: a2h.NewID(), InteractionID: m.InteractionID, RespondsTo: m.MessageID,
		Error: &a2h.ErrorInfo{Code: code, Message: message, Timestamp: now}, Timestamp: now,
	}
	raw, _ := json.Marshal(msg)
	signed, err := g.key.SignObject(raw)
	if err != nil {
		g.log.Error("sign error message", "err", err)
		return
	}
	g.enqueueWebhook(ctx, id, signed)
}

func (g *Gateway) enqueueWebhook(ctx context.Context, id string, payload []byte) {
	j := job{Kind: "webhook", InteractionID: id, Attempt: 1, RunAt: g.cfg.Now(), Payload: payload, DeliveryID: "del_" + a2h.NewID()}
	if err := g.store.addJob(ctx, g.store.db, j); err != nil {
		g.log.Error("enqueue webhook", "err", err)
	}
}

func (g *Gateway) sendWebhook(ctx context.Context, j job) {
	in, err := g.store.getInteraction(ctx, "id = ?", j.InteractionID)
	if err != nil {
		return
	}
	var m a2h.Message
	json.Unmarshal(in.Request, &m)
	if m.Callback == nil {
		return
	}
	err = g.postWebhook(ctx, m.Callback, j)
	if err == nil {
		g.log.Info("webhook delivered", "interaction", in.ID, "attempt", j.Attempt)
		return
	}
	g.log.Warn("webhook failed", "interaction", in.ID, "attempt", j.Attempt, "err", err)
	if j.Attempt < len(g.cfg.WebhookRetry) {
		next := j
		next.Attempt, next.RunAt = j.Attempt+1, g.cfg.Now().Add(g.cfg.WebhookRetry[j.Attempt])
		g.store.addJob(ctx, g.store.db, next)
		return
	}
	// Spec section 1.12.5: agents fall back to polling.
	g.store.db.ExecContext(ctx, `UPDATE interactions SET webhook_failed = 1 WHERE id = ?`, in.ID)
}

func (g *Gateway) postWebhook(ctx context.Context, cb *a2h.Callback, j job) error {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.WebhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cb.URL, bytes.NewReader(j.Payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "a2h-gateway")
	req.Header.Set(a2h.HeaderSignature, a2h.SignWebhook(cb.Secret, j.Payload, g.cfg.Now()))
	// The same ID on every retry of one event lets agents deduplicate.
	req.Header.Set(a2h.HeaderDeliveryID, j.DeliveryID)
	resp, err := g.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("callback responded %d", resp.StatusCode)
	}
	return nil
}

// answer records the principal's answer, signs the RESPONSE and notifies the
// agent. It fails if the interaction is no longer waiting for input, which
// makes every link single-use (spec section 1.10.5).
func (g *Gateway) answer(ctx context.Context, in *interaction, decision string, data map[string]any, evidence *a2h.Evidence) (*a2h.ResponseMessage, error) {
	var m a2h.Message
	if err := json.Unmarshal(in.Request, &m); err != nil {
		return nil, err
	}
	now := g.cfg.Now().UTC()
	resp := a2h.ResponseMessage{
		A2HVersion: a2h.Version, Type: a2h.Response, MessageID: a2h.NewID(), InteractionID: m.InteractionID,
		RespondsTo: m.MessageID, AgentID: m.AgentID, PrincipalID: m.PrincipalID, Status: a2h.StateAnswered,
		Decision: decision, DecidedAt: now.Format(time.RFC3339), Data: data, Evidence: evidence, CreatedAt: now.Format(time.RFC3339),
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	signed, err := g.key.SignObject(raw)
	if err != nil {
		return nil, err
	}
	res, err := g.store.db.ExecContext(ctx, `UPDATE interactions SET state = ?, response = ?, updated_at = ? WHERE id = ? AND state = ? AND expires_at > ?`,
		a2h.StateAnswered, string(signed), ms(now), in.ID, a2h.StateWaitingInput, ms(now))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, errAlreadyHandled
	}
	json.Unmarshal(signed, &resp)
	g.log.Info("answered", "interaction", in.ID, "decision", decision, "factor", evidence.Factor)
	if m.Callback != nil {
		g.enqueueWebhook(ctx, in.ID, signed)
	}
	return &resp, nil
}

var errAlreadyHandled = errors.New("interaction is no longer waiting for input")
