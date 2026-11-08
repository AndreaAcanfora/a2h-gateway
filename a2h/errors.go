package a2h

import (
	"fmt"
	"net/http"
)

// Error codes (spec section 1.3, ERROR).
const (
	ErrExpired            = "ERR.EXPIRED"
	ErrInvalidRequest     = "ERR.INVALID_REQUEST"
	ErrInvalidPrincipal   = "ERR.INVALID_PRINCIPAL"
	ErrChannelUnavailable = "ERR.CHANNEL_UNAVAILABLE"
	ErrConflict           = "ERR.CONFLICT"
	ErrReplayRejected     = "ERR.REPLAY_REJECTED"
	ErrRateLimited        = "ERR.RATE_LIMITED"
	ErrDeliveryFailed     = "ERR.DELIVERY_FAILED"
	ErrQuietHours         = "ERR.QUIET_HOURS"
	// ErrUnauthorized and ErrNotFound are not in the spec's enumeration but
	// are needed for 401 and 404 responses.
	ErrUnauthorized = "ERR.UNAUTHORIZED"
	ErrNotFound     = "ERR.NOT_FOUND"
)

// APIError is the error body of the HTTP API (OpenAPI ErrorResponse).
type APIError struct {
	Code          string         `json:"error"`
	Message       string         `json:"message"`
	Details       map[string]any `json:"details,omitempty"`
	RetryAfterSec int            `json:"retry_after_sec,omitempty"`
	// HTTPStatus is the status the error was (or is to be) sent with.
	HTTPStatus int `json:"-"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Errorf returns an APIError with the HTTP status that fits its code.
func Errorf(code, format string, args ...any) *APIError {
	return &APIError{Code: code, Message: fmt.Sprintf(format, args...), HTTPStatus: StatusFor(code)}
}

// StatusFor maps an error code to an HTTP status.
func StatusFor(code string) int {
	switch code {
	case ErrUnauthorized:
		return http.StatusUnauthorized
	case ErrNotFound, ErrInvalidPrincipal:
		return http.StatusNotFound
	case ErrConflict:
		return http.StatusConflict
	case ErrRateLimited:
		return http.StatusTooManyRequests
	case ErrChannelUnavailable, ErrQuietHours:
		return http.StatusUnprocessableEntity
	case ErrExpired:
		return http.StatusGone
	default:
		return http.StatusBadRequest
	}
}
