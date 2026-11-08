package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/channels"
	"github.com/AndreaAcanfora/a2h-gateway/gateway"
)

// person is a channel that answers every request it receives, once the
// page shows the form (the gateway records the delivery right after Deliver).
type person struct{ decision string }

func (p person) Type() string { return "console" }
func (p person) Deliver(_ context.Context, n channels.Notification) error {
	go func() {
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
		http.PostForm(n.ActionURL, url.Values{"decision": {p.decision}})
	}()
	return nil
}

func gatewayWith(t *testing.T, p person) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	g, err := gateway.New(gateway.Config{
		BaseURL: base, APIKeys: map[string]string{"cli-key-0123456789": "cli"}, Channels: []channels.Channel{p},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = g.Handler()
	ctx, cancel := context.WithCancel(context.Background())
	go g.Run(ctx)
	t.Cleanup(func() { cancel(); srv.Close(); g.Close() })
	return base
}

func TestAsk(t *testing.T) {
	for decision, want := range map[string]int{"APPROVE": 0, "DECLINE": 1} {
		base := gatewayWith(t, person{decision})
		var stdout, stderr bytes.Buffer
		code := run([]string{"ask", "-gateway", base, "-key", "cli-key-0123456789", "-to", "console:me", "-json", "Ship it?"}, &stdout, &stderr)
		if code != want {
			t.Errorf("%s: exit %d, want %d\n%s", decision, code, want, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"decision": "`+decision+`"`) || !strings.Contains(stdout.String(), `"signature"`) {
			t.Errorf("%s: stdout %s", decision, stdout.String())
		}
	}
}

func TestUsageErrors(t *testing.T) {
	var out bytes.Buffer
	t.Setenv("A2H_GATEWAY", "")
	if code := run([]string{"ask", "question"}, &out, &out); code != 2 {
		t.Errorf("ask without gateway: %d", code)
	}
	if code := run([]string{"ask", "-gateway", "http://x", "-to", "fax:123", "q"}, &out, &out); code != 2 {
		t.Errorf("unknown scheme: %d", code)
	}
	if code := run([]string{"nope"}, &out, &out); code != 2 {
		t.Errorf("unknown command: %d", code)
	}
	t.Setenv("A2H_BASE_URL", "")
	if code := run([]string{"serve"}, &out, &out); code != 2 {
		t.Errorf("serve without base URL: %d", code)
	}
}
