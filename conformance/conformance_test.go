package conformance

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AndreaAcanfora/a2h-gateway/channels"
	"github.com/AndreaAcanfora/a2h-gateway/gateway"
)

func TestReferenceGatewayConforms(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	g, err := gateway.New(gateway.Config{
		BaseURL:  base,
		APIKeys:  map[string]string{"k": "conformance"},
		Channels: []channels.Channel{channels.Console{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	srv.Config.Handler = g.Handler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)

	results := Run(ctx, Options{BaseURL: base, APIKey: "k", Channel: "console", Address: "console:test"})
	for _, r := range results {
		if !r.Passed || r.Skipped {
			t.Errorf("%s %s: %s", r.Level, r.Name, r.Detail)
		}
	}
	if len(results) < 15 {
		t.Errorf("only %d checks ran", len(results))
	}
}

// A gateway that accepts everything must fail.
func TestDetectsPermissiveGateway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/.well-known/a2h":
			json.NewEncoder(w).Encode(map[string]any{"a2h_supported": []string{"1.0"}, "channels": []string{"console"}, "factors": []string{}})
		case r.URL.Path == "/v1/intent":
			json.NewEncoder(w).Encode(map[string]any{"interaction_id": "fixed", "state": "PENDING"})
		default:
			json.NewEncoder(w).Encode(map[string]any{"interaction_id": "fixed", "state": "PENDING"})
		}
	}))
	defer srv.Close()
	results := Run(context.Background(), Options{BaseURL: srv.URL, Channel: "console", Address: "console:x"})
	if Passed(results) {
		t.Fatal("a permissive gateway passed")
	}
	failed := map[string]bool{}
	for _, r := range results {
		if !r.Passed {
			failed[r.Name] = true
		}
	}
	for _, want := range []string{"RESPONSE type from an agent is rejected", "unsupported profile is rejected", "status of an unknown interaction is 404"} {
		if !failed[want] {
			t.Errorf("%q should fail", want)
		}
	}
}
