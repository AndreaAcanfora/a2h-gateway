package a2h

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Webhook headers (spec section 1.12.3).
const (
	HeaderSignature  = "X-A2H-Signature"
	HeaderDeliveryID = "X-A2H-Delivery-ID"
	HeaderAPIKey     = "X-A2H-API-Key"
)

// SignWebhook returns the X-A2H-Signature value for a body (spec section 1.12.4).
func SignWebhook(secret string, body []byte, at time.Time) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	return "t=" + ts + ",v1=" + webhookMAC(secret, ts, body)
}

func webhookMAC(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// ErrWebhookSignature is returned by VerifyWebhook for bad or stale signatures.
var ErrWebhookSignature = errors.New("a2h: invalid webhook signature")

// VerifyWebhook checks an X-A2H-Signature header, rejecting timestamps more
// than tolerance away from now (the spec uses 5 minutes).
func VerifyWebhook(secret, header string, body []byte, now time.Time, tolerance time.Duration) error {
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return ErrWebhookSignature
	}
	if d := now.Sub(time.Unix(sec, 0)); d > tolerance || d < -tolerance {
		return fmt.Errorf("%w: timestamp outside tolerance", ErrWebhookSignature)
	}
	want := webhookMAC(secret, ts, body)
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(want)) {
			return nil
		}
	}
	return ErrWebhookSignature
}

// NewID returns a UUIDv7 (RFC 9562), the ID format the spec uses for
// interactions and messages.
func NewID() string {
	return newUUIDv7(time.Now())
}

func newUUIDv7(t time.Time) string {
	var b [16]byte
	rand.Read(b[:])
	ms := uint64(t.UnixMilli())
	b[0], b[1], b[2], b[3], b[4], b[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
