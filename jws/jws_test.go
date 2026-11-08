package jws

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := JWKS{Keys: []JWK{k.PublicJWK()}}
	msg := []byte(`{"type":"RESPONSE","decision":"APPROVE","n":1.50,"nested":{"b":1,"a":2}}`)
	signed, err := k.SignObject(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, keys); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Formatting and member order do not matter: the payload is canonical.
	var obj map[string]any
	json.Unmarshal(signed, &obj)
	reordered, _ := json.MarshalIndent(obj, "", "  ")
	if err := Verify(reordered, keys); err != nil {
		t.Fatalf("verify reformatted: %v", err)
	}
	// Any change to the content breaks the signature.
	tampered := strings.Replace(string(signed), "APPROVE", "DECLINE", 1)
	if err := Verify([]byte(tampered), keys); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered message: %v", err)
	}
	// A different key does not verify.
	other, _ := GenerateKey()
	o := other.PublicJWK()
	o.Kid = k.ID
	if err := Verify(signed, JWKS{Keys: []JWK{o}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong key: %v", err)
	}
	if err := Verify(signed, JWKS{}); err == nil {
		t.Fatal("empty key set accepted")
	}
	sig := obj["signature"].(string)
	if !strings.Contains(sig, "..") {
		t.Errorf("not detached: %s", sig)
	}
}

func TestPEMRoundTrip(t *testing.T) {
	k, _ := GenerateKey()
	p, err := k.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePEM(p)
	if err != nil || k2.ID != k.ID {
		t.Fatalf("round trip: %v %s %s", err, k.ID, k2.ID)
	}
	if _, err := ParsePEM([]byte("nope")); err == nil {
		t.Error("garbage accepted")
	}
}

// RFC 7638 section 3.1 example uses RSA; for EC, check the thumbprint is
// stable and matches the JWK it came from.
func TestThumbprint(t *testing.T) {
	k, _ := GenerateKey()
	j := k.PublicJWK()
	p, err := j.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if Thumbprint(p) != j.Kid || len(j.Kid) != 43 {
		t.Errorf("thumbprint %s vs kid %s", Thumbprint(p), j.Kid)
	}
	bad := j
	bad.X = j.Y
	if _, err := bad.PublicKey(); err == nil {
		t.Error("point off the curve accepted")
	}
}
