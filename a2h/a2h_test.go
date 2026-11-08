package a2h

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestWebhookSignature(t *testing.T) {
	now := time.Unix(1705667100, 0)
	body := []byte(`{"type":"RESPONSE"}`)
	h := SignWebhook("whsec_x", body, now)
	if !regexp.MustCompile(`^t=1705667100,v1=[0-9a-f]{64}$`).MatchString(h) {
		t.Fatalf("header %q", h)
	}
	if err := VerifyWebhook("whsec_x", h, body, now.Add(time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"wrong secret": func() error { return VerifyWebhook("other", h, body, now, 5*time.Minute) },
		"changed body": func() error { return VerifyWebhook("whsec_x", h, []byte(`{}`), now, 5*time.Minute) },
		"stale":        func() error { return VerifyWebhook("whsec_x", h, body, now.Add(6*time.Minute), 5*time.Minute) },
		"garbage":      func() error { return VerifyWebhook("whsec_x", "nope", body, now, 5*time.Minute) },
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, ErrWebhookSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Several v1 values (key rotation) are accepted if one matches.
	if err := VerifyWebhook("whsec_x", strings.Replace(h, ",v1=", ",v1=deadbeef,v1=", 1), body, now, time.Minute); err != nil {
		t.Errorf("rotation: %v", err)
	}
}

func TestNewID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	a, b := NewID(), NewID()
	if !re.MatchString(a) || a == b {
		t.Fatalf("ids %s %s", a, b)
	}
	// UUIDv7 sorts by time.
	early := newUUIDv7(time.Unix(1000, 0))
	late := newUUIDv7(time.Unix(2000, 0))
	if early >= late {
		t.Errorf("%s >= %s", early, late)
	}
}

func TestStates(t *testing.T) {
	if !Terminal(StateSent, Inform) || Terminal(StateSent, Authorize) || Terminal(StateWaitingInput, Collect) || !Terminal(StateExpired, Authorize) {
		t.Error("terminal states")
	}
}

func TestVersionChecks(t *testing.T) {
	l := Limits{Channels: []string{"email"}}
	base := func() *Message {
		return &Message{Type: Inform, MessageID: "m", AgentID: "a", PrincipalID: "p", Channel: &Channel{Type: "email", Address: "mailto:a@b.c"}, Render: &Render{Body: "x"}}
	}
	m := base()
	if err := m.Validate(l); err != nil || m.A2HVersion != "1.0" || m.TTLSec != DefaultTTLSec {
		t.Fatalf("defaults: %v %+v", err, m)
	}
	m = base()
	m.A2HVersion = "2.0"
	if m.Validate(l) == nil {
		t.Error("2.0 accepted")
	}
	m = base()
	m.A2HVersion, m.A2HMinVersion = "1.3", "1.0"
	if err := m.Validate(l); err != nil {
		t.Errorf("1.3 with min 1.0: %v", err)
	}
	if compareVersions("1.10", "1.9") != 1 || compareVersions("1.0", "1") != 0 {
		t.Error("compareVersions")
	}
	// channel.render wins over render.
	m = base()
	m.Channel.Render = &Render{Body: "short"}
	if m.EffectiveRender().Body != "short" {
		t.Error("channel.render ignored")
	}
}

func TestValidateAnswer(t *testing.T) {
	min, ml := 1.0, 3
	cs := []Component{
		{Type: "TEXT", Name: "code", Required: true, Validation: &Validation{Pattern: "[A-Z]{3}", MaxLength: &ml}},
		{Type: "NUMBER", Name: "n", Validation: &Validation{Min: &min}},
		{Type: "DATE", Name: "day"},
		{Type: "RADIO", Name: "r", Options: []Option{{Value: "a"}, {Value: "b"}}},
		{Type: "CHECKBOX", Name: "ok"},
	}
	data, problems := ValidateAnswer(cs, map[string][]string{"code": {"ABC"}, "n": {"2.5"}, "day": {"2026-11-08"}, "r": {"b"}})
	if len(problems) != 0 || data["code"] != "ABC" || data["n"] != 2.5 || data["day"] != "2026-11-08" || data["r"] != "b" || data["ok"] != false {
		t.Fatalf("data %v problems %v", data, problems)
	}
	// The pattern must match the whole value.
	_, problems = ValidateAnswer(cs, map[string][]string{"code": {"ABCD"}, "n": {"0"}, "day": {"08/11/2026"}, "r": {"z"}})
	for _, f := range []string{"code", "n", "day", "r"} {
		if problems[f] == "" {
			t.Errorf("%s accepted", f)
		}
	}
	_, problems = ValidateAnswer(cs, map[string][]string{})
	if problems["code"] != "required" || len(problems) != 1 {
		t.Errorf("required: %v", problems)
	}
}
