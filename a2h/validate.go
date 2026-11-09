package a2h

import (
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Limits are the gateway settings that validation depends on.
type Limits struct {
	MaxTTLSec       int
	Channels        []string
	Factors         []string
	Profiles        []string
	InsecureWebhook bool // accept http:// callback URLs (development only)
}

// DefaultTTLSec is the TTL of intents that do not set one (OpenAPI default).
const DefaultTTLSec = 300

var componentTypes = []string{"TEXT", "SELECT", "MULTISELECT", "CHECKBOX", "RADIO", "TEXTAREA", "NUMBER", "DATE", "TIME", "DATETIME"}

var componentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// Validate checks an intent sent by an agent and fills in defaults
// (a2h_version, ttl_sec). It returns an ERR.INVALID_REQUEST error, or
// ERR.CHANNEL_UNAVAILABLE for channels the gateway cannot use.
func (m *Message) Validate(l Limits) *APIError {
	bad := func(field, format string, args ...any) *APIError {
		e := Errorf(ErrInvalidRequest, format, args...)
		e.Details = map[string]any{"field": field}
		return e
	}
	if m.A2HVersion == "" {
		m.A2HVersion = Version
	}
	if major, _, _ := strings.Cut(m.A2HVersion, "."); major != "1" {
		return bad("a2h_version", "unsupported version %q", m.A2HVersion)
	}
	if m.A2HMinVersion != "" && compareVersions(m.A2HMinVersion, Version) > 0 {
		return bad("a2h_min_version", "gateway supports A2H %s, sender requires %s", Version, m.A2HMinVersion)
	}
	switch m.Type {
	case Inform, Collect, Authorize, Escalate, Result:
	case Response, Error:
		return bad("type", "%s messages are sent by the gateway, not to it", m.Type)
	default:
		return bad("type", "unknown type %q", m.Type)
	}
	if n := len(m.MessageID); n < 1 || n > 256 {
		return bad("message_id", "message_id must have 1 to 256 characters")
	}
	if n := len(m.PrincipalID); n < 1 || n > 256 {
		return bad("principal_id", "principal_id must have 1 to 256 characters")
	}
	if m.AgentID == "" {
		return bad("agent_id", "agent_id is required")
	}
	if m.Profile != "" && !slices.Contains(l.Profiles, m.Profile) {
		// Spec section 1.5: unsupported profiles MUST be rejected.
		return bad("profile", "profile %q is not supported by this gateway", m.Profile)
	}
	if m.Channel == nil {
		return bad("channel", "channel is required")
	}
	if err := validateChannel(m.Channel.Type, m.Channel.Address, "channel", l); err != nil {
		return err
	}
	for i, f := range m.Channel.Fallback {
		if err := validateChannel(f.Type, f.Address, "channel.fallback["+strconv.Itoa(i)+"]", l); err != nil {
			return err
		}
	}
	r := m.EffectiveRender()
	if r == nil || r.Body == "" {
		return bad("render.body", "render.body is required")
	}
	if len(r.Body) > 4096 || len(r.Title) > 256 || len(r.Footer) > 512 {
		return bad("render", "render content is too long")
	}
	if m.TTLSec == 0 {
		m.TTLSec = DefaultTTLSec
	}
	maxTTL := 86400
	if l.MaxTTLSec > 0 && l.MaxTTLSec < maxTTL {
		maxTTL = l.MaxTTLSec
	}
	if m.TTLSec < 30 || m.TTLSec > maxTTL {
		return bad("ttl_sec", "ttl_sec must be between 30 and %d", maxTTL)
	}
	if m.Assurance != nil {
		if m.Assurance.Level != "" && !slices.Contains([]string{"LOW", "MEDIUM", "HIGH"}, m.Assurance.Level) {
			return bad("assurance.level", "unknown assurance level %q", m.Assurance.Level)
		}
		for _, f := range m.Assurance.RequiredFactors {
			if !slices.Contains(l.Factors, f) {
				return bad("assurance.required_factors", "factor %q is not supported by this gateway", f)
			}
		}
	}
	if m.Callback != nil {
		u, err := url.Parse(m.Callback.URL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(l.InsecureWebhook && u.Scheme == "http")) {
			return bad("callback.url", "callback.url must be an absolute HTTPS URL")
		}
		if m.Callback.Secret == "" {
			return bad("callback.secret", "callback.secret is required")
		}
	}
	if m.Type == Collect {
		if err := validateComponents(m.Components); err != nil {
			return err
		}
	}
	if m.CreatedAt != "" {
		if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
			return bad("created_at", "created_at must be an RFC 3339 timestamp")
		}
	}
	return nil
}

// EffectiveRender returns the content to show: channel.render wins over render.
func (m *Message) EffectiveRender() *Render {
	if m.Channel != nil && m.Channel.Render != nil && m.Channel.Render.Body != "" {
		return m.Channel.Render
	}
	return m.Render
}

// RequiresPasskey reports whether an approval needs a passkey assertion.
func (m *Message) RequiresPasskey() bool {
	return m.Assurance != nil && (m.Assurance.Level == "HIGH" || slices.Contains(m.Assurance.RequiredFactors, FactorPasskey))
}

// Address schemes accepted for each channel type.
var channelSchemes = map[string][]string{
	"email":    {"mailto"},
	"push":     {"https", "http"},
	"telegram": {"tg"},
	"console":  {"console"},
	"app":      {"app"},
}

func validateChannel(typ, address, field string, l Limits) *APIError {
	if typ == "" || address == "" {
		e := Errorf(ErrInvalidRequest, "%s needs a type and an address", field)
		e.Details = map[string]any{"field": field}
		return e
	}
	if !slices.Contains(l.Channels, typ) {
		e := Errorf(ErrChannelUnavailable, "channel %q is not available on this gateway", typ)
		e.Details = map[string]any{"field": field + ".type", "available": l.Channels}
		return e
	}
	scheme, _, ok := strings.Cut(address, ":")
	if schemes, known := channelSchemes[typ]; ok && known && !slices.Contains(schemes, strings.ToLower(scheme)) {
		e := Errorf(ErrInvalidRequest, "a %s address must use the %s scheme", typ, strings.Join(schemes, " or "))
		e.Details = map[string]any{"field": field + ".address"}
		return e
	} else if !ok {
		e := Errorf(ErrInvalidRequest, "%s.address must be a URI (tel:, mailto:, …)", field)
		e.Details = map[string]any{"field": field + ".address"}
		return e
	}
	return nil
}

func validateComponents(cs []Component) *APIError {
	bad := func(i int, format string, args ...any) *APIError {
		e := Errorf(ErrInvalidRequest, format, args...)
		e.Details = map[string]any{"field": "components[" + strconv.Itoa(i) + "]"}
		return e
	}
	if len(cs) == 0 {
		e := Errorf(ErrInvalidRequest, "COLLECT needs at least one component")
		e.Details = map[string]any{"field": "components"}
		return e
	}
	seen := map[string]bool{}
	for i, c := range cs {
		if !slices.Contains(componentTypes, c.Type) {
			return bad(i, "unknown component type %q", c.Type)
		}
		if !componentName.MatchString(c.Name) {
			return bad(i, "invalid component name %q", c.Name)
		}
		if seen[c.Name] {
			return bad(i, "duplicate component name %q", c.Name)
		}
		seen[c.Name] = true
		if (c.Type == "SELECT" || c.Type == "MULTISELECT" || c.Type == "RADIO") && len(c.Options) == 0 {
			return bad(i, "%s needs options", c.Type)
		}
		if c.Validation != nil && c.Validation.Pattern != "" {
			if _, err := regexp.Compile(c.Validation.Pattern); err != nil {
				return bad(i, "invalid pattern: %v", err)
			}
		}
	}
	return nil
}

// compareVersions compares dotted versions numerically.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ValidateAnswer checks the data a principal submitted for a COLLECT form and
// returns the typed values to put in the RESPONSE.
func ValidateAnswer(cs []Component, form map[string][]string) (map[string]any, map[string]string) {
	data := map[string]any{}
	problems := map[string]string{}
	for _, c := range cs {
		values := form[c.Name]
		first := ""
		if len(values) > 0 {
			first = strings.TrimSpace(values[0])
		}
		switch c.Type {
		case "CHECKBOX":
			data[c.Name] = first == "on" || first == "true"
			continue
		case "MULTISELECT":
			var picked []string
			for _, v := range values {
				if hasOption(c.Options, v) {
					picked = append(picked, v)
				} else {
					problems[c.Name] = "not one of the options"
				}
			}
			if c.Required && len(picked) == 0 {
				problems[c.Name] = "required"
			}
			data[c.Name] = picked
			continue
		}
		if first == "" {
			if c.Required {
				problems[c.Name] = "required"
			}
			continue
		}
		switch c.Type {
		case "SELECT", "RADIO":
			if !hasOption(c.Options, first) {
				problems[c.Name] = "not one of the options"
				continue
			}
			data[c.Name] = first
		case "NUMBER":
			n, err := strconv.ParseFloat(first, 64)
			if err != nil {
				problems[c.Name] = "not a number"
				continue
			}
			if v := c.Validation; v != nil && ((v.Min != nil && n < *v.Min) || (v.Max != nil && n > *v.Max)) {
				problems[c.Name] = "out of range"
				continue
			}
			data[c.Name] = n
		case "DATE", "TIME", "DATETIME":
			layout := map[string]string{"DATE": "2006-01-02", "TIME": "15:04", "DATETIME": "2006-01-02T15:04"}[c.Type]
			if _, err := time.Parse(layout, first); err != nil {
				problems[c.Name] = "invalid " + strings.ToLower(c.Type)
				continue
			}
			data[c.Name] = first
		default: // TEXT, TEXTAREA
			if v := c.Validation; v != nil {
				n := len([]rune(first))
				if (v.MinLength != nil && n < *v.MinLength) || (v.MaxLength != nil && n > *v.MaxLength) {
					problems[c.Name] = "wrong length"
					continue
				}
				if v.Pattern != "" {
					if re, err := regexp.Compile(`^(?:` + v.Pattern + `)$`); err == nil && !re.MatchString(first) {
						problems[c.Name] = "invalid format"
						continue
					}
				}
			}
			data[c.Name] = first
		}
	}
	return data, problems
}

func hasOption(opts []Option, v string) bool {
	for _, o := range opts {
		if o.Value == v {
			return true
		}
	}
	return false
}
