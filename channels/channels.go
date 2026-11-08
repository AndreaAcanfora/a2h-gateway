// Package channels delivers A2H messages to people: email, push (ntfy),
// Telegram, and the console for development.
package channels

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// Notification is what a channel shows to the principal.
type Notification struct {
	InteractionID string
	Intent        string // INFORM, COLLECT, AUTHORIZE, ESCALATE, RESULT
	Title         string
	Body          string
	Why           string
	// ActionURL opens the page where the principal answers or reads more.
	ActionURL string
	ExpiresAt time.Time
	Address   string // channel.address, e.g. mailto:alice@example.com
}

// Channel delivers notifications of one type.
type Channel interface {
	Type() string
	Deliver(ctx context.Context, n Notification) error
}

// PermanentError marks failures that retrying cannot fix (invalid address,
// blocked recipient). Other errors are treated as transient.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps err as a PermanentError.
func Permanent(err error) error { return &PermanentError{Err: err} }

// IsPermanent reports whether err is permanent.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}

func actionLabel(intent string) string {
	switch intent {
	case "AUTHORIZE":
		return "Review and decide"
	case "COLLECT":
		return "Answer"
	default:
		return "Open"
	}
}

func plainText(n Notification) string {
	var b strings.Builder
	b.WriteString(n.Body)
	if n.Why != "" {
		b.WriteString("\n\nWhy: " + n.Why)
	}
	if n.ActionURL != "" {
		b.WriteString("\n\n" + actionLabel(n.Intent) + ": " + n.ActionURL)
	}
	if !n.ExpiresAt.IsZero() {
		b.WriteString("\n\nThis request expires at " + n.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC") + ".")
	}
	return b.String()
}

// Console logs notifications instead of delivering them. For development:
// the action URL appears in the gateway's log. Addresses are console:<name>.
type Console struct{ Log *slog.Logger }

func (Console) Type() string { return "console" }

func (c Console) Deliver(_ context.Context, n Notification) error {
	log := c.Log
	if log == nil {
		log = slog.Default()
	}
	log.Info("console delivery", "to", n.Address, "intent", n.Intent, "title", n.Title, "body", n.Body, "url", n.ActionURL)
	return nil
}

// Email sends notifications over SMTP. Addresses are mailto:user@example.com.
type Email struct {
	Host     string // smtp.example.com
	Port     int    // 587 (STARTTLS) or 465 (TLS)
	Username string
	Password string
	From     string // "A2H Gateway <a2h@example.com>"
	// Insecure allows plain-text SMTP without TLS (local test servers only).
	Insecure bool
}

func (Email) Type() string { return "email" }

func (e Email) Deliver(ctx context.Context, n Notification) error {
	to, err := mailtoAddress(n.Address)
	if err != nil {
		return Permanent(err)
	}
	from, err := mail.ParseAddress(e.From)
	if err != nil {
		return Permanent(fmt.Errorf("email: invalid From address: %w", err))
	}
	subject := n.Title
	if subject == "" {
		subject = map[string]string{"AUTHORIZE": "Approval needed", "COLLECT": "Information needed"}[n.Intent]
		if subject == "" {
			subject = "Message from your agent"
		}
	}
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n",
		from.String(), to, mime.QEncoding.Encode("utf-8", subject), time.Now().Format(time.RFC1123Z))
	if n.InteractionID != "" {
		fmt.Fprintf(&msg, "X-A2H-Interaction-ID: %s\r\n", n.InteractionID)
	}
	msg.WriteString("\r\n")
	msg.WriteString(strings.ReplaceAll(plainText(n), "\n", "\r\n"))
	msg.WriteString("\r\n")
	return e.send(ctx, from.Address, to, msg.Bytes())
}

func mailtoAddress(address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "mailto" || u.Opaque == "" {
		return "", fmt.Errorf("email: %q is not a mailto: address", address)
	}
	a, err := mail.ParseAddress(u.Opaque)
	if err != nil {
		return "", fmt.Errorf("email: invalid address %q", u.Opaque)
	}
	return a.Address, nil
}

func (e Email) send(ctx context.Context, from, to string, msg []byte) error {
	addr := net.JoinHostPort(e.Host, fmt.Sprint(e.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if e.Port == 465 {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: e.Host})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("email: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(60 * time.Second))
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("email: %w", err)
	}
	defer c.Close()
	if e.Port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: e.Host}); err != nil {
				return fmt.Errorf("email: STARTTLS: %w", err)
			}
		} else if !e.Insecure {
			return errors.New("email: server does not offer STARTTLS")
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return Permanent(fmt.Errorf("email: authentication failed: %w", err))
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("email: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		// 5xx replies to RCPT TO mean the address is not deliverable.
		if strings.HasPrefix(err.Error(), "5") {
			return Permanent(fmt.Errorf("email: recipient rejected: %w", err))
		}
		return fmt.Errorf("email: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return c.Quit()
}

// Ntfy publishes push notifications to an ntfy server (https://ntfy.sh or
// self-hosted). The address is the topic URL, e.g. https://ntfy.sh/my-secret-topic.
type Ntfy struct {
	HTTP *http.Client
	// Token is an optional access token for protected topics.
	Token string
}

func (Ntfy) Type() string { return "push" }

func (p Ntfy) Deliver(ctx context.Context, n Notification) error {
	u, err := url.Parse(n.Address)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || strings.Trim(u.Path, "/") == "" {
		return Permanent(fmt.Errorf("push: %q is not an ntfy topic URL", n.Address))
	}
	body := n.Body
	if n.Why != "" {
		body += "\n\nWhy: " + n.Why
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body))
	if err != nil {
		return Permanent(err)
	}
	if n.Title != "" {
		req.Header.Set("Title", mime.QEncoding.Encode("utf-8", n.Title))
	}
	if n.ActionURL != "" {
		req.Header.Set("Click", n.ActionURL)
		req.Header.Set("Actions", "view, "+actionLabel(n.Intent)+", "+n.ActionURL+", clear=true")
	}
	if n.Intent == "AUTHORIZE" {
		req.Header.Set("Priority", "high")
		req.Header.Set("Tags", "lock")
	}
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	return doHTTP(p.HTTP, req, "push")
}

// Telegram sends messages through a Telegram bot. The address is
// tg:<chat_id>; the principal must have started a chat with the bot.
type Telegram struct {
	HTTP    *http.Client
	Token   string
	APIBase string // default https://api.telegram.org
}

func (Telegram) Type() string { return "telegram" }

func (t Telegram) Deliver(ctx context.Context, n Notification) error {
	chat, ok := strings.CutPrefix(n.Address, "tg:")
	if !ok || chat == "" {
		return Permanent(fmt.Errorf("telegram: %q is not a tg:<chat_id> address", n.Address))
	}
	text := plainText(n)
	if n.Title != "" {
		text = n.Title + "\n\n" + text
	}
	payload := map[string]any{"chat_id": chat, "text": text, "disable_web_page_preview": true}
	if n.ActionURL != "" {
		payload["reply_markup"] = map[string]any{"inline_keyboard": [][]map[string]string{{{"text": actionLabel(n.Intent), "url": n.ActionURL}}}}
	}
	b, _ := json.Marshal(payload)
	base := t.APIBase
	if base == "" {
		base = "https://api.telegram.org"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/bot"+t.Token+"/sendMessage", bytes.NewReader(b))
	if err != nil {
		return Permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return doHTTP(t.HTTP, req, "telegram")
}

func doHTTP(client *http.Client, req *http.Request, name string) error {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		// Strip the URL: for Telegram it contains the bot token.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("%s: server responded %d", name, resp.StatusCode)
	default:
		return Permanent(fmt.Errorf("%s: server responded %d: %s", name, resp.StatusCode, bytes.TrimSpace(msg)))
	}
}
