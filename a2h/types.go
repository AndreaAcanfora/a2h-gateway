// Package a2h holds the message types of the A2H (Agent-to-Human) protocol
// v1.0, their validation, webhook signatures and a client for agents.
//
// The protocol is specified by Twilio Labs at
// https://github.com/twilio-labs/Agent2Human. This package is an independent
// implementation.
package a2h

import "encoding/json"

// Version is the protocol version implemented here.
const Version = "1.0"

// Intent and message types (spec section 1.3).
const (
	Inform    = "INFORM"
	Collect   = "COLLECT"
	Authorize = "AUTHORIZE"
	Escalate  = "ESCALATE"
	Result    = "RESULT"
	Response  = "RESPONSE"
	Error     = "ERROR"
)

// Interaction states (spec section 1.6).
const (
	StatePending      = "PENDING"
	StateSent         = "SENT"
	StateWaitingInput = "WAITING_INPUT"
	StateAnswered     = "ANSWERED"
	StateExpired      = "EXPIRED"
	StateCancelled    = "CANCELLED"
	StateFailed       = "FAILED"
)

// Terminal reports whether no further transition can happen from state.
// SENT is terminal for intents that expect no answer (INFORM, RESULT, ESCALATE).
func Terminal(state, intent string) bool {
	switch state {
	case StateAnswered, StateExpired, StateCancelled, StateFailed:
		return true
	case StateSent:
		return !ExpectsInput(intent)
	}
	return false
}

// ExpectsInput reports whether an intent waits for a human RESPONSE.
func ExpectsInput(intent string) bool {
	return intent == Authorize || intent == Collect
}

// Decisions of a RESPONSE to AUTHORIZE.
const (
	Approve = "APPROVE"
	Decline = "DECLINE"
)

// Authentication factors.
const (
	FactorPasskey   = "passkey.webauthn.v1"
	FactorEmailLink = "email_link.v1"
	FactorLink      = "link.v1"
	// FactorDeviceKey is an answer signed by a key that lives on a paired
	// phone app (an extension of this gateway, not in the A2H spec).
	FactorDeviceKey = "device_key.es256.v1"
)

// Message is the common envelope of every A2H message (spec section 1.2).
type Message struct {
	A2HVersion        string            `json:"a2h_version,omitempty"`
	A2HMinVersion     string            `json:"a2h_min_version,omitempty"`
	InteractionID     string            `json:"interaction_id,omitempty"`
	Type              string            `json:"type"`
	MessageID         string            `json:"message_id"`
	RespondsTo        string            `json:"responds_to,omitempty"`
	AgentID           string            `json:"agent_id"`
	PrincipalID       string            `json:"principal_id"`
	Profile           string            `json:"profile,omitempty"`
	Channel           *Channel          `json:"channel,omitempty"`
	Render            *Render           `json:"render,omitempty"`
	Links             map[string]string `json:"links,omitempty"`
	Params            map[string]any    `json:"params,omitempty"`
	TTLSec            int               `json:"ttl_sec,omitempty"`
	Assurance         *Assurance        `json:"assurance,omitempty"`
	ExplanationBundle map[string]any    `json:"explanation_bundle,omitempty"`
	Callback          *Callback         `json:"callback,omitempty"`
	Components        []Component       `json:"components,omitempty"`
	CreatedAt         string            `json:"created_at,omitempty"`
	Signature         string            `json:"signature,omitempty"`
}

// Channel says where to deliver a message (spec sections 1.9 and 1.13).
type Channel struct {
	Type      string       `json:"type"`
	Address   string       `json:"address"`
	Nonce     string       `json:"nonce,omitempty"`
	ExpiresAt string       `json:"expires_at,omitempty"`
	Render    *Render      `json:"render,omitempty"`
	Fallback  []ChannelRef `json:"fallback,omitempty"`
}

// ChannelRef is a fallback channel.
type ChannelRef struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

// Render is the human-readable content of a message.
type Render struct {
	Title  string `json:"title,omitempty"`
	Body   string `json:"body"`
	Footer string `json:"footer,omitempty"`
	Icon   string `json:"icon,omitempty"`
}

// Assurance asks for a level of proof that the principal decided.
type Assurance struct {
	Level           string   `json:"level,omitempty"`
	RequiredFactors []string `json:"required_factors,omitempty"`
}

// Callback is where the gateway POSTs the outcome (spec section 1.12).
type Callback struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// Component is one input of a COLLECT form.
type Component struct {
	Type       string      `json:"type"`
	Name       string      `json:"name"`
	Label      string      `json:"label,omitempty"`
	Required   bool        `json:"required,omitempty"`
	Validation *Validation `json:"validation,omitempty"`
	Options    []Option    `json:"options,omitempty"`
}

// Validation constrains a COLLECT input.
type Validation struct {
	Pattern   string   `json:"pattern,omitempty"`
	Min       *float64 `json:"min,omitempty"`
	Max       *float64 `json:"max,omitempty"`
	MinLength *int     `json:"minLength,omitempty"`
	MaxLength *int     `json:"maxLength,omitempty"`
}

// Option is a choice of a SELECT, MULTISELECT or RADIO input.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

// ResponseMessage is the human's reply, signed by the gateway (spec sections 1.3 and 1.11).
type ResponseMessage struct {
	A2HVersion    string         `json:"a2h_version"`
	Type          string         `json:"type"`
	MessageID     string         `json:"message_id"`
	InteractionID string         `json:"interaction_id"`
	RespondsTo    string         `json:"responds_to"`
	AgentID       string         `json:"agent_id,omitempty"`
	PrincipalID   string         `json:"principal_id"`
	Status        string         `json:"status"`
	Decision      string         `json:"decision,omitempty"`
	DecidedAt     string         `json:"decided_at"`
	Data          map[string]any `json:"data,omitempty"`
	Evidence      *Evidence      `json:"evidence,omitempty"`
	CreatedAt     string         `json:"created_at"`
	Signature     string         `json:"signature,omitempty"`
}

// ErrorMessage is an A2H ERROR message, sent to webhooks when an interaction
// ends without an answer.
type ErrorMessage struct {
	A2HVersion    string     `json:"a2h_version"`
	Type          string     `json:"type"`
	MessageID     string     `json:"message_id"`
	InteractionID string     `json:"interaction_id"`
	RespondsTo    string     `json:"responds_to"`
	Error         *ErrorInfo `json:"error"`
	Timestamp     string     `json:"timestamp"`
	Signature     string     `json:"signature,omitempty"`
}

// Evidence is the proof of the principal's decision (spec section 1.11.3).
type Evidence struct {
	Factor string         `json:"factor"`
	Proof  map[string]any `json:"proof"`
}

// IntentResponse is the answer of POST /v1/intent.
type IntentResponse struct {
	InteractionID string `json:"interaction_id"`
	State         string `json:"state"`
	CreatedAt     string `json:"created_at"`
	TTLSec        int    `json:"ttl_sec"`
	ChannelID     string `json:"channel_id,omitempty"`
	Duplicate     bool   `json:"duplicate,omitempty"`
}

// InteractionStatus is the answer of GET /v1/status/{id}.
type InteractionStatus struct {
	InteractionID string          `json:"interaction_id"`
	Type          string          `json:"type"`
	State         string          `json:"state"`
	CreatedAt     string          `json:"created_at"`
	UpdatedAt     string          `json:"updated_at"`
	ExpiresAt     string          `json:"expires_at,omitempty"`
	ChannelID     string          `json:"channel_id,omitempty"`
	Response      json.RawMessage `json:"response,omitempty"`
	Error         *ErrorInfo      `json:"error,omitempty"`
	WebhookFailed bool            `json:"webhook_failed,omitempty"`
}

// ErrorInfo describes why an interaction failed.
type ErrorInfo struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp,omitempty"`
}

// Capabilities is the discovery document at /.well-known/a2h (spec section 1.4).
type Capabilities struct {
	A2HSupported     []string          `json:"a2h_supported"`
	Channels         []string          `json:"channels"`
	Factors          []string          `json:"factors"`
	MaxTTLSec        int               `json:"max_ttl_sec,omitempty"`
	Locales          []string          `json:"locales,omitempty"`
	JWKSURI          string            `json:"jwks_uri,omitempty"`
	Auth             *AuthInfo         `json:"auth,omitempty"`
	ReplayProtection *ReplayProtection `json:"replay_protection,omitempty"`
	Webhooks         *WebhookInfo      `json:"webhooks,omitempty"`
	Profiles         []string          `json:"profiles"`
}

// AuthInfo lists the authentication methods of a gateway.
type AuthInfo struct {
	Methods []string `json:"methods"`
}

// ReplayProtection describes a gateway's replay protection (spec section 1.10.2).
type ReplayProtection struct {
	IdempotencyWindowSec  int    `json:"idempotency_window_sec"`
	TimestampToleranceSec int    `json:"timestamp_tolerance_sec"`
	NonceEndpoint         string `json:"nonce_endpoint,omitempty"`
}

// WebhookInfo describes a gateway's webhooks (spec section 1.12.8).
type WebhookInfo struct {
	Supported     bool `json:"supported"`
	RetryAttempts int  `json:"retry_attempts"`
	TimeoutSec    int  `json:"timeout_sec"`
}

// Nonce is the answer of GET /v1/nonce.
type Nonce struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}
