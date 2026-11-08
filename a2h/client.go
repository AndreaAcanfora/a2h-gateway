package a2h

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/jws"
)

// Client talks to an A2H gateway on behalf of an agent.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client

	mu   sync.Mutex
	jwks *jws.JWKS
}

// NewClient returns a client for the gateway at baseURL.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set(HeaderAPIKey, c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		apiErr := &APIError{HTTPStatus: resp.StatusCode}
		if json.Unmarshal(data, apiErr) != nil || apiErr.Code == "" {
			apiErr.Code, apiErr.Message = "HTTP", strings.TrimSpace(string(data))
		}
		return apiErr
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Capabilities fetches /.well-known/a2h.
func (c *Client) Capabilities(ctx context.Context) (*Capabilities, error) {
	var caps Capabilities
	return &caps, c.do(ctx, http.MethodGet, "/.well-known/a2h", nil, &caps)
}

// Send submits an intent. It fills in message_id and created_at when empty.
func (c *Client) Send(ctx context.Context, m *Message) (*IntentResponse, error) {
	if m.MessageID == "" {
		m.MessageID = NewID()
	}
	if m.CreatedAt == "" {
		m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if m.A2HVersion == "" {
		m.A2HVersion = Version
	}
	var r IntentResponse
	return &r, c.do(ctx, http.MethodPost, "/v1/intent", m, &r)
}

// Status fetches the state of an interaction.
func (c *Client) Status(ctx context.Context, interactionID string) (*InteractionStatus, error) {
	var s InteractionStatus
	return &s, c.do(ctx, http.MethodGet, "/v1/status/"+url.PathEscape(interactionID), nil, &s)
}

// Cancel cancels an interaction that is waiting for input.
func (c *Client) Cancel(ctx context.Context, interactionID string) error {
	return c.do(ctx, http.MethodPost, "/v1/cancel/"+url.PathEscape(interactionID), nil, nil)
}

// GetNonce asks for a one-time nonce (spec section 1.10.4).
func (c *Client) GetNonce(ctx context.Context) (*Nonce, error) {
	var n Nonce
	return &n, c.do(ctx, http.MethodGet, "/v1/nonce", nil, &n)
}

// Wait polls an interaction until it reaches a terminal state or ctx ends.
func (c *Client) Wait(ctx context.Context, interactionID string, every time.Duration) (*InteractionStatus, error) {
	if every <= 0 {
		every = 2 * time.Second
	}
	for {
		s, err := c.Status(ctx, interactionID)
		if err != nil {
			var apiErr *APIError
			// Network errors and 5xx are worth retrying; anything else is final.
			if errors.As(err, &apiErr) && apiErr.HTTPStatus < 500 {
				return nil, err
			}
		} else if Terminal(s.State, s.Type) {
			return s, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(every):
		}
	}
}

// JWKS fetches (and caches) the gateway's signing keys.
func (c *Client) JWKS(ctx context.Context) (*jws.JWKS, error) {
	c.mu.Lock()
	cached := c.jwks
	c.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	caps, err := c.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	u := caps.JWKSURI
	if u == "" {
		u = c.BaseURL + "/.well-known/jwks.json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set jws.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("a2h: reading JWKS: %w", err)
	}
	c.mu.Lock()
	c.jwks = &set
	c.mu.Unlock()
	return &set, nil
}

// VerifyResponse checks a RESPONSE as spec section 1.11.7 requires: it must
// answer originalMessageID and carry a valid gateway signature.
func (c *Client) VerifyResponse(ctx context.Context, raw []byte, originalMessageID string) (*ResponseMessage, error) {
	var r ResponseMessage
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.Type != Response {
		return nil, fmt.Errorf("a2h: expected a RESPONSE, got %q", r.Type)
	}
	if r.RespondsTo != originalMessageID {
		return nil, fmt.Errorf("a2h: response answers %q, not %q", r.RespondsTo, originalMessageID)
	}
	keys, err := c.JWKS(ctx)
	if err != nil {
		return nil, err
	}
	if err := jws.Verify(raw, *keys); err != nil {
		// The key may have rotated: refresh once.
		c.mu.Lock()
		c.jwks = nil
		c.mu.Unlock()
		if keys, err2 := c.JWKS(ctx); err2 != nil || jws.Verify(raw, *keys) != nil {
			return nil, err
		}
	}
	return &r, nil
}
