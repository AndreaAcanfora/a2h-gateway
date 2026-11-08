// Package mcpserver exposes an A2H gateway to AI agents as MCP tools: ask a
// person for approval or information, notify them, follow up on a request.
//
// The person to contact is fixed by configuration, never chosen by the model,
// so an agent cannot message arbitrary people.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Config says whom to contact and how.
type Config struct {
	// Channel and Address of the person, e.g. "email" and "mailto:me@example.com".
	Channel, Address string
	PrincipalID      string
	AgentID          string
	// MaxWait bounds how long one tool call blocks waiting for an answer.
	// Longer waits continue with check_request.
	MaxWait time.Duration
	// PollEvery is the status polling interval.
	PollEvery time.Duration
	Version   string
}

type server struct {
	cfg    Config
	client *a2h.Client
	mu     sync.Mutex
	sent   map[string]string // interaction ID → message ID, to verify answers
}

// New returns an MCP server backed by an A2H gateway client.
func New(client *a2h.Client, cfg Config) *mcp.Server {
	if cfg.MaxWait == 0 {
		cfg.MaxWait = 10 * time.Minute
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 2 * time.Second
	}
	if cfg.AgentID == "" {
		cfg.AgentID = "mcp:a2h"
	}
	s := &server{cfg: cfg, client: client, sent: map[string]string{}}
	srv := mcp.NewServer(&mcp.Implementation{Name: "a2h", Title: "A2H: ask a human", Version: cfg.Version}, &mcp.ServerOptions{
		Instructions: "Use these tools to involve the human you work for: request_approval before irreversible, costly or sensitive actions; " +
			"ask_human when you need information only they have; notify_human to report progress or results. " +
			"The human answers from their phone or email, which can take minutes. If a call returns while still waiting, use check_request later. " +
			"Never proceed with an action that was declined, expired or cancelled.",
	})
	open, closed := true, false
	mcp.AddTool(srv, &mcp.Tool{
		Name:  "request_approval",
		Title: "Request approval from the human",
		Description: "Ask the human to approve or decline an action before you take it. Blocks until they answer or wait_seconds pass. " +
			"Returns decision APPROVE or DECLINE with a verified, signed record of who decided. Proceed only on APPROVE.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: &open, DestructiveHint: &closed},
	}, s.requestApproval)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ask_human",
		Title:       "Ask the human for information",
		Description: "Ask the human to fill in a short form (text, numbers, dates, choices). Blocks until they answer or wait_seconds pass.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: &open, DestructiveHint: &closed},
	}, s.askHuman)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "notify_human",
		Title:       "Notify the human",
		Description: "Send the human a short message (progress, result, alert). Does not wait for an answer.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: &open, DestructiveHint: &closed},
	}, s.notifyHuman)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "check_request",
		Title:       "Check a request",
		Description: "Get the state of an earlier request_approval or ask_human, optionally waiting for the answer.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &open},
	}, s.checkRequest)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "cancel_request",
		Title:       "Cancel a request",
		Description: "Withdraw a request that the human has not answered yet, so that it can no longer be approved.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: &open, IdempotentHint: true, DestructiveHint: &closed},
	}, s.cancelRequest)
	return srv
}

// ApprovalInput is the input of request_approval.
type ApprovalInput struct {
	Question       string `json:"question" jsonschema:"what you want to do, as a yes/no question the human can decide on its own, e.g. Delete the 3 unused S3 buckets listed below?"`
	Title          string `json:"title,omitempty" jsonschema:"short title for the notification"`
	Why            string `json:"why,omitempty" jsonschema:"why you need this and what happens if approved; mention anything irreversible"`
	TimeoutMinutes int    `json:"timeout_minutes,omitempty" jsonschema:"minutes the human has to answer (default 30, max 1440)"`
	RequirePasskey bool   `json:"require_passkey,omitempty" jsonschema:"require the human to confirm with a passkey; use for payments and other high-stakes actions"`
	WaitSeconds    *int   `json:"wait_seconds,omitempty" jsonschema:"how long this call waits for the answer (default and maximum set by the server); 0 returns at once"`
}

// Field is one input of ask_human.
type Field struct {
	Name     string   `json:"name" jsonschema:"identifier of the answer, e.g. arrival_date"`
	Label    string   `json:"label,omitempty" jsonschema:"question shown to the human"`
	Type     string   `json:"type,omitempty" jsonschema:"text (default), long_text, number, date, time, choice, multichoice or yes_no"`
	Options  []string `json:"options,omitempty" jsonschema:"possible answers for choice and multichoice"`
	Required bool     `json:"required,omitempty"`
}

// AskInput is the input of ask_human.
type AskInput struct {
	Question       string  `json:"question" jsonschema:"what you need and why"`
	Title          string  `json:"title,omitempty"`
	Fields         []Field `json:"fields" jsonschema:"the answers you need, at least one"`
	TimeoutMinutes int     `json:"timeout_minutes,omitempty" jsonschema:"minutes the human has to answer (default 30, max 1440)"`
	WaitSeconds    *int    `json:"wait_seconds,omitempty" jsonschema:"how long this call waits for the answer; 0 returns at once"`
}

// NotifyInput is the input of notify_human.
type NotifyInput struct {
	Message string `json:"message"`
	Title   string `json:"title,omitempty"`
	Topic   string `json:"topic,omitempty" jsonschema:"receipt, progress, alert, result or exception"`
}

// CheckInput is the input of check_request and cancel_request.
type CheckInput struct {
	InteractionID string `json:"interaction_id"`
	WaitSeconds   *int   `json:"wait_seconds,omitempty" jsonschema:"check_request only: how long to wait for an answer; 0 (default) returns at once"`
}

// Outcome describes a request after a tool call.
type Outcome struct {
	InteractionID string         `json:"interaction_id"`
	State         string         `json:"state" jsonschema:"WAITING (no answer yet), ANSWERED, EXPIRED, CANCELLED or FAILED"`
	Decision      string         `json:"decision,omitempty" jsonschema:"APPROVE or DECLINE, for approvals"`
	Data          map[string]any `json:"data,omitempty" jsonschema:"the human's answers, for ask_human"`
	DecidedAt     string         `json:"decided_at,omitempty"`
	Factor        string         `json:"factor,omitempty" jsonschema:"how the human proved it was them, e.g. passkey.webauthn.v1"`
	Verified      bool           `json:"verified,omitempty" jsonschema:"the gateway's signature on the answer was checked"`
	Message       string         `json:"message"`
}

func ttl(minutes int) int {
	switch {
	case minutes <= 0:
		return 30 * 60
	case minutes > 1440:
		return 1440 * 60
	default:
		return minutes * 60
	}
}

func (s *server) waitFor(p *int) time.Duration {
	if p == nil {
		return s.cfg.MaxWait
	}
	d := time.Duration(*p) * time.Second
	return min(max(d, 0), s.cfg.MaxWait)
}

func (s *server) message(typ, title, body string) *a2h.Message {
	return &a2h.Message{
		Type: typ, AgentID: s.cfg.AgentID, PrincipalID: s.cfg.PrincipalID,
		Channel: &a2h.Channel{Type: s.cfg.Channel, Address: s.cfg.Address},
		Render:  &a2h.Render{Title: title, Body: body},
	}
}

func (s *server) send(ctx context.Context, m *a2h.Message) (string, error) {
	r, err := s.client.Send(ctx, m)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.sent[r.InteractionID] = m.MessageID
	s.mu.Unlock()
	return r.InteractionID, nil
}

func (s *server) requestApproval(ctx context.Context, req *mcp.CallToolRequest, in ApprovalInput) (*mcp.CallToolResult, Outcome, error) {
	if strings.TrimSpace(in.Question) == "" {
		return nil, Outcome{}, errors.New("question is required")
	}
	title := in.Title
	if title == "" {
		title = "Approval needed"
	}
	m := s.message(a2h.Authorize, title, in.Question)
	m.TTLSec = ttl(in.TimeoutMinutes)
	if in.Why != "" {
		m.ExplanationBundle = map[string]any{"why": in.Why}
	}
	if in.RequirePasskey {
		m.Assurance = &a2h.Assurance{Level: "HIGH", RequiredFactors: []string{a2h.FactorPasskey}}
	}
	id, err := s.send(ctx, m)
	if err != nil {
		return nil, Outcome{}, fmt.Errorf("sending the request: %w", err)
	}
	return s.follow(ctx, req, id, s.waitFor(in.WaitSeconds))
}

var fieldTypes = map[string]string{
	"": "TEXT", "text": "TEXT", "long_text": "TEXTAREA", "number": "NUMBER", "date": "DATE",
	"time": "TIME", "choice": "SELECT", "multichoice": "MULTISELECT", "yes_no": "RADIO",
}

func (s *server) askHuman(ctx context.Context, req *mcp.CallToolRequest, in AskInput) (*mcp.CallToolResult, Outcome, error) {
	if strings.TrimSpace(in.Question) == "" || len(in.Fields) == 0 {
		return nil, Outcome{}, errors.New("question and at least one field are required")
	}
	m := s.message(a2h.Collect, in.Title, in.Question)
	m.TTLSec = ttl(in.TimeoutMinutes)
	for _, f := range in.Fields {
		typ, ok := fieldTypes[f.Type]
		if !ok {
			return nil, Outcome{}, fmt.Errorf("field %q: unknown type %q", f.Name, f.Type)
		}
		c := a2h.Component{Type: typ, Name: f.Name, Label: f.Label, Required: f.Required}
		if f.Type == "yes_no" {
			c.Options = []a2h.Option{{Value: "yes", Label: "Yes"}, {Value: "no", Label: "No"}}
		}
		for _, o := range f.Options {
			c.Options = append(c.Options, a2h.Option{Value: o, Label: o})
		}
		m.Components = append(m.Components, c)
	}
	id, err := s.send(ctx, m)
	if err != nil {
		return nil, Outcome{}, fmt.Errorf("sending the request: %w", err)
	}
	return s.follow(ctx, req, id, s.waitFor(in.WaitSeconds))
}

func (s *server) notifyHuman(ctx context.Context, _ *mcp.CallToolRequest, in NotifyInput) (*mcp.CallToolResult, Outcome, error) {
	if strings.TrimSpace(in.Message) == "" {
		return nil, Outcome{}, errors.New("message is required")
	}
	m := s.message(a2h.Inform, in.Title, in.Message)
	if in.Topic != "" {
		m.Params = map[string]any{"topic": in.Topic}
	}
	id, err := s.send(ctx, m)
	if err != nil {
		return nil, Outcome{}, fmt.Errorf("sending the message: %w", err)
	}
	return nil, Outcome{InteractionID: id, State: "SENT", Message: "Message sent to the human."}, nil
}

func (s *server) checkRequest(ctx context.Context, req *mcp.CallToolRequest, in CheckInput) (*mcp.CallToolResult, Outcome, error) {
	if in.InteractionID == "" {
		return nil, Outcome{}, errors.New("interaction_id is required")
	}
	wait := time.Duration(0)
	if in.WaitSeconds != nil {
		wait = s.waitFor(in.WaitSeconds)
	}
	return s.follow(ctx, req, in.InteractionID, wait)
}

func (s *server) cancelRequest(ctx context.Context, _ *mcp.CallToolRequest, in CheckInput) (*mcp.CallToolResult, Outcome, error) {
	if err := s.client.Cancel(ctx, in.InteractionID); err != nil {
		var apiErr *a2h.APIError
		if errors.As(err, &apiErr) && apiErr.Code == a2h.ErrConflict {
			_, out, err := s.follow(ctx, nil, in.InteractionID, 0)
			out.Message = "Too late to cancel: " + out.Message
			return nil, out, err
		}
		return nil, Outcome{}, err
	}
	return nil, Outcome{InteractionID: in.InteractionID, State: a2h.StateCancelled, Message: "Request cancelled: it can no longer be approved."}, nil
}

// follow polls a request until it is answered, ends, or wait elapses,
// sending progress notifications so that clients do not time out.
func (s *server) follow(ctx context.Context, req *mcp.CallToolRequest, id string, wait time.Duration) (*mcp.CallToolResult, Outcome, error) {
	deadline := time.Now().Add(wait)
	var token any
	if req != nil {
		token = req.Params.GetProgressToken()
	}
	lastProgress := time.Now()
	for {
		st, err := s.client.Status(ctx, id)
		if err != nil {
			return nil, Outcome{}, fmt.Errorf("checking the request: %w", err)
		}
		if a2h.Terminal(st.State, st.Type) || !time.Now().Before(deadline) {
			out, err := s.outcome(ctx, st)
			return nil, out, err
		}
		if token != nil && time.Since(lastProgress) >= 10*time.Second {
			req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				ProgressToken: token, Progress: time.Since(deadline.Add(-wait)).Seconds(), Total: wait.Seconds(),
				Message: "Waiting for the human to answer…",
			})
			lastProgress = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil, Outcome{}, ctx.Err()
		case <-time.After(min(s.cfg.PollEvery, time.Until(deadline)+time.Millisecond)):
		}
	}
}

func (s *server) outcome(ctx context.Context, st *a2h.InteractionStatus) (Outcome, error) {
	out := Outcome{InteractionID: st.InteractionID, State: st.State}
	switch st.State {
	case a2h.StateAnswered:
		s.mu.Lock()
		messageID, known := s.sent[st.InteractionID]
		s.mu.Unlock()
		if !known {
			var r a2h.ResponseMessage
			json.Unmarshal(st.Response, &r)
			messageID = r.RespondsTo
		}
		resp, err := s.client.VerifyResponse(ctx, st.Response, messageID)
		if err != nil {
			// Never report an unverified answer as a decision.
			return Outcome{InteractionID: st.InteractionID, State: "FAILED", Message: "The answer could not be verified: " + err.Error() + ". Do not proceed."}, nil
		}
		out.Decision, out.Data, out.DecidedAt, out.Verified = resp.Decision, resp.Data, resp.DecidedAt, true
		if resp.Evidence != nil {
			out.Factor = resp.Evidence.Factor
		}
		switch resp.Decision {
		case a2h.Approve:
			out.Message = "The human APPROVED. You may proceed."
		case a2h.Decline:
			out.Message = "The human DECLINED. Do not proceed."
		default:
			out.Message = "The human answered."
		}
	case a2h.StateExpired:
		out.Message = "The human did not answer in time. Do not proceed; ask again only if still needed."
	case a2h.StateCancelled:
		out.Message = "The request was cancelled. Do not proceed."
	case a2h.StateFailed:
		out.Message = "The request could not be delivered"
		if st.Error != nil {
			out.Message += ": " + st.Error.Message
		}
		out.Message += ". Do not proceed."
	default:
		out.State = "WAITING"
		out.Message = "No answer yet. Call check_request with this interaction_id later; do not proceed meanwhile."
	}
	return out, nil
}
