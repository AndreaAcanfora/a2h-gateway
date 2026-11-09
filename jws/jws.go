// Package jws signs and verifies A2H messages: a detached JWS (RFC 7515,
// appendix F) with ES256 over the JCS form of the message without its
// "signature" member, as A2H sections 1.1 and 1.11.2 describe.
package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/AndreaAcanfora/a2h-gateway/jcs"
)

var b64 = base64.RawURLEncoding

// Key is a P-256 signing key with its key ID (the RFC 7638 thumbprint).
type Key struct {
	Private *ecdsa.PrivateKey
	ID      string
}

// GenerateKey returns a new signing key.
func GenerateKey() (*Key, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return newKey(k), nil
}

func newKey(k *ecdsa.PrivateKey) *Key {
	return &Key{Private: k, ID: Thumbprint(&k.PublicKey)}
}

// MarshalPEM encodes the private key as PKCS#8 PEM.
func (k *Key) MarshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePEM decodes a key written by MarshalPEM.
func ParsePEM(data []byte) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("jws: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("jws: not a P-256 key")
	}
	return newKey(ec), nil
}

// JWK is a public key in JSON Web Key form.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// coords returns the base64url coordinates of a P-256 public key.
func coords(p *ecdsa.PublicKey) (x, y string) {
	b, _ := p.Bytes() // 0x04 || X || Y
	return b64.EncodeToString(b[1:33]), b64.EncodeToString(b[33:65])
}

// PublicJWK returns the public half of k.
func (k *Key) PublicJWK() JWK {
	x, y := coords(&k.Private.PublicKey)
	return JWK{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: k.ID, Alg: "ES256", Use: "sig"}
}

// Thumbprint returns the RFC 7638 thumbprint of a P-256 public key.
func Thumbprint(p *ecdsa.PublicKey) string {
	x, y := coords(p)
	required, _ := jcs.Marshal(map[string]string{"crv": "P-256", "kty": "EC", "x": x, "y": y})
	sum := sha256.Sum256(required)
	return b64.EncodeToString(sum[:])
}

// PublicKey converts a JWK back to a public key.
func (j JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("jws: unsupported key type %s/%s", j.Kty, j.Crv)
	}
	x, err1 := b64.DecodeString(j.X)
	y, err2 := b64.DecodeString(j.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("jws: invalid EC coordinates")
	}
	p, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, errors.New("jws: point not on curve")
	}
	return p, nil
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// signingPayload returns the JCS form of a JSON object without "signature".
func signingPayload(message []byte) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(message, &obj); err != nil {
		return nil, fmt.Errorf("jws: message is not a JSON object: %w", err)
	}
	delete(obj, "signature")
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return jcs.Canonicalize(raw)
}

// Sign returns the detached compact JWS of a JSON message: "header..signature".
func (k *Key) Sign(message []byte) (string, error) {
	payload, err := signingPayload(message)
	if err != nil {
		return "", err
	}
	h, _ := json.Marshal(header{Alg: "ES256", Kid: k.ID})
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.Private, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return b64.EncodeToString(h) + ".." + b64.EncodeToString(sig), nil
}

// SignObject sets the "signature" member of a JSON object and returns the result.
func (k *Key) SignObject(message []byte) ([]byte, error) {
	sig, err := k.Sign(message)
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(message, &obj); err != nil {
		return nil, err
	}
	obj["signature"], _ = json.Marshal(sig)
	return json.Marshal(obj)
}

// ErrInvalid is returned for signatures that do not verify.
var ErrInvalid = errors.New("jws: invalid signature")

// Verify checks the "signature" member of a JSON message against a key set.
func Verify(message []byte, keys JWKS) error {
	var obj struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(message, &obj); err != nil {
		return fmt.Errorf("jws: %w", err)
	}
	if obj.Signature == "" {
		return errors.New("jws: message has no signature")
	}
	return VerifyDetached(message, obj.Signature, keys)
}

// VerifyDetached checks a detached JWS over a JSON message.
func VerifyDetached(message []byte, compact string, keys JWKS) error {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[1] != "" {
		return errors.New("jws: not a detached compact JWS")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return ErrInvalid
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "ES256" {
		return fmt.Errorf("jws: unsupported header %s", hb)
	}
	var key *ecdsa.PublicKey
	for _, j := range keys.Keys {
		if j.Kid == h.Kid || (h.Kid == "" && len(keys.Keys) == 1) {
			if key, err = j.PublicKey(); err != nil {
				return err
			}
			break
		}
	}
	if key == nil {
		return fmt.Errorf("jws: no key with kid %q", h.Kid)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return ErrInvalid
	}
	payload, err := signingPayload(message)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + b64.EncodeToString(payload)))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return ErrInvalid
	}
	return nil
}

// VerifyCompact checks an attached compact JWS ("header.payload.signature",
// ES256) against key and returns its header and payload.
func VerifyCompact(compact string, key *ecdsa.PublicKey) (hdr, payload []byte, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[1] == "" {
		return nil, nil, errors.New("jws: not a compact JWS")
	}
	if hdr, err = b64.DecodeString(parts[0]); err != nil {
		return nil, nil, ErrInvalid
	}
	var h header
	if err := json.Unmarshal(hdr, &h); err != nil || h.Alg != "ES256" {
		return nil, nil, fmt.Errorf("jws: unsupported header %s", hdr)
	}
	if payload, err = b64.DecodeString(parts[1]); err != nil {
		return nil, nil, ErrInvalid
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, nil, ErrInvalid
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, nil, ErrInvalid
	}
	return hdr, payload, nil
}
