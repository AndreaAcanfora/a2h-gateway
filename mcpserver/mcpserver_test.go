package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/AndreaAcanfora/a2h-gateway/channels"
	"github.com/AndreaAcanfora/a2h-gateway/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// person answers requests through the real web pages, as a human would.
type person struct {
	mu      sync.Mutex
	answer  url.Values // nil: never answer
	got     []channels.Notification
	delayed time.Duration
}

func (p *person) Type() string { return "console" }
func (p *person) Deliver(_ context.Context, n channels.Notification) error {
	p.mu.Lock()
	p.got = append(p.got, n)
	answer := p.answer
	p.mu.Unlock()
	if answer == nil || n.Intent == a2h.Inform {
		return nil
	}
	go func() {
		time.Sleep(p.delayed)
		for range 100 {
			if resp, err := http.Get(n.ActionURL); err == nil {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if strings.Contains(string(b), "<form") {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		http.PostForm(n.ActionURL, answer)
	}()
	return nil
}

// delivered waits until the person received n notifications.
func (p *person) delivered(t *testing.T, n int) channels.Notification {
	t.Helper()
	for range 200 {
		p.mu.Lock()
		if len(p.got) >= n {
			got := p.got[n-1]
			p.mu.Unlock()
			return got
		}
		p.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("notification %d never arrived", n)
	return channels.Notification{}
}

func connect(t *testing.T, p *person) *mcp.ClientSession {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	g, err := gateway.New(gateway.Config{
		BaseURL: base, APIKeys: map[string]string{"mcp-key-0123456789": "mcp"}, Channels: []channels.Channel{p},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = g.Handler()
	ctx, cancel := context.WithCancel(context.Background())
	go g.Run(ctx)

	server := New(a2h.NewClient(base, "mcp-key-0123456789"), Config{
		Channel: "console", Address: "console:me", PrincipalID: "usr_me", MaxWait: 20 * time.Second, PollEvery: 50 * time.Millisecond, Version: "test",
	})
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); cancel(); srv.Close(); g.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) Outcome {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError {
		b, _ := json.Marshal(res.Content)
		t.Fatalf("%s returned an error: %s", tool, b)
	}
	var out Outcome
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &out)
	return out
}

func TestTools(t *testing.T) {
	cs := connect(t, &person{})
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
		if tl.Description == "" || tl.InputSchema == nil {
			t.Errorf("%s lacks a description or schema", tl.Name)
		}
	}
	if strings.Join(names, ",") != "ask_human,cancel_request,check_request,notify_human,request_approval" {
		t.Errorf("tools %v", names)
	}
	// The recipient is configuration, not an argument the model controls.
	for _, tl := range tools.Tools {
		schema, _ := json.Marshal(tl.InputSchema)
		for _, forbidden := range []string{"address", "channel", "principal", "\"to\""} {
			if strings.Contains(string(schema), forbidden) {
				t.Errorf("%s lets the model choose %s: %s", tl.Name, forbidden, schema)
			}
		}
	}
}

func TestApproval(t *testing.T) {
	for decision, msg := range map[string]string{"APPROVE": "APPROVED", "DECLINE": "DECLINED"} {
		p := &person{answer: url.Values{"decision": {decision}}}
		cs := connect(t, p)
		out := call(t, cs, "request_approval", map[string]any{"question": "Delete 3 unused buckets?", "why": "They cost 40 EUR a month."})
		if out.State != a2h.StateAnswered || out.Decision != decision || !out.Verified || out.Factor != a2h.FactorLink || !strings.Contains(out.Message, msg) {
			t.Errorf("%s: %+v", decision, out)
		}
		if n := p.delivered(t, 1); n.Intent != a2h.Authorize || n.Address != "console:me" || n.Why != "They cost 40 EUR a month." || n.Title != "Approval needed" {
			t.Errorf("notification %+v", n)
		}
	}
}

func TestPasskeyRequestIsMarkedHigh(t *testing.T) {
	p := &person{}
	cs := connect(t, p)
	out := call(t, cs, "request_approval", map[string]any{"question": "Pay 900 EUR?", "require_passkey": true, "wait_seconds": 0})
	if out.State != "WAITING" || out.InteractionID == "" {
		t.Fatalf("%+v", out)
	}
	resp, _ := http.Get(p.delivered(t, 1).ActionURL)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "needs a passkey") {
		t.Errorf("the request does not require a passkey")
	}
}

func TestWaitingThenCheck(t *testing.T) {
	p := &person{answer: url.Values{"decision": {"APPROVE"}}, delayed: 500 * time.Millisecond}
	cs := connect(t, p)
	out := call(t, cs, "request_approval", map[string]any{"question": "Ship it?", "wait_seconds": 0})
	if out.State != "WAITING" || !strings.Contains(out.Message, "check_request") {
		t.Fatalf("immediate return: %+v", out)
	}
	later := call(t, cs, "check_request", map[string]any{"interaction_id": out.InteractionID, "wait_seconds": 10})
	if later.Decision != a2h.Approve || !later.Verified {
		t.Errorf("after waiting: %+v", later)
	}
}

func TestAskHuman(t *testing.T) {
	p := &person{answer: url.Values{"decision": {"SUBMIT"}, "city": {"Lisbon"}, "nights": {"3"}, "breakfast": {"yes"}}}
	cs := connect(t, p)
	out := call(t, cs, "ask_human", map[string]any{
		"question": "Where should I book the hotel?",
		"fields": []map[string]any{
			{"name": "city", "label": "City", "required": true},
			{"name": "nights", "type": "number"},
			{"name": "breakfast", "type": "yes_no"},
		},
	})
	want := map[string]any{"city": "Lisbon", "nights": 3.0, "breakfast": "yes"}
	for k, v := range want {
		if out.Data[k] != v {
			t.Errorf("data %v", out.Data)
			break
		}
	}
	if out.Decision != "" || !out.Verified {
		t.Errorf("%+v", out)
	}
}

func TestNotifyAndCancel(t *testing.T) {
	p := &person{}
	cs := connect(t, p)
	n := call(t, cs, "notify_human", map[string]any{"message": "Backup finished: 12 GB.", "topic": "result"})
	if n.State != "SENT" {
		t.Errorf("notify %+v", n)
	}
	out := call(t, cs, "request_approval", map[string]any{"question": "Restart the database?", "wait_seconds": 0})
	p.delivered(t, 2)
	time.Sleep(100 * time.Millisecond) // the state changes right after delivery
	c := call(t, cs, "cancel_request", map[string]any{"interaction_id": out.InteractionID})
	if c.State != a2h.StateCancelled {
		t.Errorf("cancel %+v", c)
	}
	again := call(t, cs, "cancel_request", map[string]any{"interaction_id": out.InteractionID})
	if !strings.HasPrefix(again.Message, "Too late to cancel") || again.State != a2h.StateCancelled {
		t.Errorf("second cancel %+v", again)
	}
	if st := call(t, cs, "check_request", map[string]any{"interaction_id": out.InteractionID}); !strings.Contains(st.Message, "Do not proceed") {
		t.Errorf("check after cancel %+v", st)
	}
}

func TestBadInput(t *testing.T) {
	cs := connect(t, &person{})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "ask_human", Arguments: map[string]any{"question": "x", "fields": []map[string]any{{"name": "a", "type": "colour"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("unknown field type accepted")
	}
}
