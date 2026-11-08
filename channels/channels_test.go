package channels

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var note = Notification{
	InteractionID: "0190-abc",
	Intent:        "AUTHORIZE",
	Title:         "Approve deploy?",
	Body:          "Deploy v2.3 to production.",
	Why:           "It restarts the API.",
	ActionURL:     "https://gw.example/i/tok",
	ExpiresAt:     time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC),
}

func TestNtfy(t *testing.T) {
	var got *http.Request
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, body = r, string(b)
	}))
	defer srv.Close()
	n := note
	n.Address = srv.URL + "/my-topic"
	if err := (Ntfy{Token: "tk"}).Deliver(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if got.URL.Path != "/my-topic" || got.Header.Get("Click") != n.ActionURL || got.Header.Get("Priority") != "high" || got.Header.Get("Authorization") != "Bearer tk" {
		t.Errorf("request %s %v", got.URL, got.Header)
	}
	if !strings.Contains(got.Header.Get("Actions"), "view, Review and decide, https://gw.example/i/tok") {
		t.Errorf("actions %q", got.Header.Get("Actions"))
	}
	if !strings.Contains(body, "Deploy v2.3") || !strings.Contains(body, "Why: It restarts") {
		t.Errorf("body %q", body)
	}
	n.Address = "https://ntfy.sh/"
	if err := (Ntfy{}).Deliver(context.Background(), n); !IsPermanent(err) {
		t.Errorf("topic-less URL: %v", err)
	}
}

func TestHTTPErrorClasses(t *testing.T) {
	status := 503
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	n := note
	n.Address = srv.URL + "/t"
	if err := (Ntfy{}).Deliver(context.Background(), n); err == nil || IsPermanent(err) {
		t.Errorf("503 should be transient: %v", err)
	}
	status = 403
	if err := (Ntfy{}).Deliver(context.Background(), n); !IsPermanent(err) {
		t.Errorf("403 should be permanent: %v", err)
	}
}

func TestTelegram(t *testing.T) {
	var path string
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		json.NewDecoder(r.Body).Decode(&payload)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	n := note
	n.Address = "tg:12345"
	tg := Telegram{Token: "123:secret", APIBase: srv.URL}
	if err := tg.Deliver(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if path != "/bot123:secret/sendMessage" || payload["chat_id"] != "12345" {
		t.Errorf("path %s payload %v", path, payload)
	}
	kb, _ := json.Marshal(payload["reply_markup"])
	if !strings.Contains(string(kb), `"url":"https://gw.example/i/tok"`) {
		t.Errorf("keyboard %s", kb)
	}
	if !strings.HasPrefix(payload["text"].(string), "Approve deploy?\n\nDeploy v2.3") {
		t.Errorf("text %q", payload["text"])
	}
	n.Address = "telegram:1"
	if err := tg.Deliver(context.Background(), n); !IsPermanent(err) {
		t.Errorf("bad address: %v", err)
	}
	// Network errors must not leak the bot token.
	srv.Close()
	n.Address = "tg:1"
	err := tg.Deliver(context.Background(), n)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaks the token or is nil: %v", err)
	}
}

// fakeSMTP is a minimal SMTP server that records one message.
func fakeSMTP(t *testing.T, rcptReply string) (port int, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		say := func(s string) { conn.Write([]byte(s + "\r\n")) }
		say("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					got <- data.String()
					say("250 queued")
					continue
				}
				data.WriteString(line)
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "MAIL FROM"):
				say("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO"):
				say(rcptReply)
			case cmd == "DATA":
				inData = true
				say("354 go ahead")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

func TestEmail(t *testing.T) {
	port, got := fakeSMTP(t, "250 ok")
	e := Email{Host: "127.0.0.1", Port: port, From: "A2H <a2h@example.com>", Insecure: true}
	n := note
	n.Address = "mailto:alice@example.com"
	if err := e.Deliver(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	for _, want := range []string{"To: alice@example.com", "Subject: Approve deploy?", "X-A2H-Interaction-ID: 0190-abc", "Review and decide: https://gw.example/i/tok", "expires at 2026-11-08 12:00 UTC"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
}

func TestEmailErrors(t *testing.T) {
	port, _ := fakeSMTP(t, "550 no such user")
	e := Email{Host: "127.0.0.1", Port: port, From: "a2h@example.com", Insecure: true}
	n := note
	n.Address = "mailto:ghost@example.com"
	if err := e.Deliver(context.Background(), n); !IsPermanent(err) {
		t.Errorf("550 should be permanent: %v", err)
	}
	n.Address = "tel:+1555"
	if err := e.Deliver(context.Background(), n); !IsPermanent(err) {
		t.Errorf("non-mailto address: %v", err)
	}
	// Without STARTTLS and without Insecure, refuse to send in clear text.
	port2, _ := fakeSMTP(t, "250 ok")
	strict := Email{Host: "127.0.0.1", Port: port2, From: "a2h@example.com"}
	n.Address = "mailto:alice@example.com"
	if err := strict.Deliver(context.Background(), n); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("plain-text SMTP accepted: %v", err)
	}
}
