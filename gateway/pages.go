package gateway

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
)

type pageData struct {
	Token, Intent, Heading, Body, Footer, Why, Agent string
	Notice, Problem, Expires                         string
	Problems                                         map[string]string
	Values                                           url.Values
	Components                                       []a2h.Component
	Targets                                          []link
	Open, Done, Passkey, NoPasskey                   bool
	Enroll                                           bool
	Principal                                        string
	PasskeyCount                                     int
}

func (g *Gateway) renderPage(w http.ResponseWriter, status int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, d); err != nil {
		g.log.Error("render page", "err", err)
	}
}

var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{
	"value": func(v url.Values, name string) string { return v.Get(name) },
	"has": func(v url.Values, name, option string) bool {
		for _, x := range v[name] {
			if x == option {
				return true
			}
		}
		return false
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Heading}}</title>
<style>
  :root { color-scheme: light dark; --accent: #2563eb; --bad: #b91c1c; font-family: system-ui, sans-serif; }
  body { max-width: 34rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  .card { border: 1px solid #8884; border-radius: .75rem; padding: 1.25rem 1.5rem; }
  h1 { font-size: 1.35rem; margin-top: 0; }
  .body { white-space: pre-wrap; }
  .why { border-left: 3px solid var(--accent); padding-left: .75rem; color: #888; }
  .meta { font-size: .85rem; color: #888; }
  .actions { display: flex; gap: .75rem; flex-wrap: wrap; margin-top: 1.25rem; }
  button { font: inherit; padding: .65rem 1.2rem; border-radius: .5rem; border: 1px solid #8886; cursor: pointer; background: transparent; color: inherit; }
  button.primary { background: var(--accent); border-color: var(--accent); color: white; }
  label { display: block; margin-top: .9rem; font-weight: 600; }
  input, select, textarea { font: inherit; width: 100%; box-sizing: border-box; padding: .5rem; margin-top: .25rem; }
  input[type=checkbox], input[type=radio] { width: auto; }
  .choice { font-weight: normal; margin-top: .25rem; }
  .problem { color: var(--bad); font-size: .9rem; }
  .notice { font-weight: 600; }
</style>
</head>
<body>
<main class="card">
<h1>{{.Heading}}</h1>
{{if .Enroll}}
  <p>Create a passkey for <strong>{{.Principal}}</strong>. You will use it to approve sensitive requests from your agents.</p>
  {{if .PasskeyCount}}<p class="meta">You already have {{.PasskeyCount}} passkey(s). This adds another one.</p>{{end}}
  <div class="actions"><button class="primary" id="enroll">Create passkey</button></div>
  <p id="status" class="notice" role="status"></p>
{{else}}
  {{if .Body}}<p class="body">{{.Body}}</p>{{end}}
  {{if .Why}}<p class="why">{{.Why}}</p>{{end}}
  {{range .Targets}}<p>{{if .URL}}<a href="{{.URL}}">{{.Label}}</a>{{else}}{{.Label}}{{end}}</p>{{end}}
  {{if .Footer}}<p class="meta">{{.Footer}}</p>{{end}}
  {{if .Problem}}<p class="problem" role="alert">{{.Problem}}</p>{{end}}
  {{if .Open}}
    {{if eq .Intent "AUTHORIZE"}}
      {{if .Passkey}}
        {{if .NoPasskey}}<p class="problem">This request needs a passkey, and none is enrolled for you yet. Ask the gateway operator for an enrollment link.</p>{{end}}
        <div class="actions">
          {{if not .NoPasskey}}<button class="primary" id="approve-passkey">Approve with passkey</button>{{end}}
          <form method="post"><input type="hidden" name="decision" value="DECLINE"><button>Decline</button></form>
        </div>
        <p id="status" class="notice" role="status"></p>
      {{else}}
        <form method="post" class="actions">
          <button class="primary" name="decision" value="APPROVE">Approve</button>
          <button name="decision" value="DECLINE">Decline</button>
        </form>
      {{end}}
    {{else if eq .Intent "COLLECT"}}
      <form method="post">
        {{$v := .Values}}{{$p := .Problems}}
        {{range .Components}}
          {{$label := .Label}}{{if not $label}}{{$label = .Name}}{{end}}
          {{if eq .Type "CHECKBOX"}}
            <label class="choice"><input type="checkbox" name="{{.Name}}" {{if value $v .Name}}checked{{end}}> {{$label}}</label>
          {{else if or (eq .Type "RADIO") (eq .Type "MULTISELECT")}}
            <label>{{$label}}{{if .Required}} *{{end}}</label>
            {{$name := .Name}}{{$type := .Type}}
            {{range .Options}}<label class="choice"><input type="{{if eq $type "RADIO"}}radio{{else}}checkbox{{end}}" name="{{$name}}" value="{{.Value}}" {{if has $v $name .Value}}checked{{end}}> {{if .Label}}{{.Label}}{{else}}{{.Value}}{{end}}</label>{{end}}
          {{else}}
            <label for="f-{{.Name}}">{{$label}}{{if .Required}} *{{end}}</label>
            {{if eq .Type "SELECT"}}
              {{$name := .Name}}
              <select id="f-{{.Name}}" name="{{.Name}}" {{if .Required}}required{{end}}><option value=""></option>{{range .Options}}<option value="{{.Value}}" {{if eq (value $v $name) .Value}}selected{{end}}>{{if .Label}}{{.Label}}{{else}}{{.Value}}{{end}}</option>{{end}}</select>
            {{else if eq .Type "TEXTAREA"}}
              <textarea id="f-{{.Name}}" name="{{.Name}}" rows="4" {{if .Required}}required{{end}}>{{value $v .Name}}</textarea>
            {{else}}
              <input id="f-{{.Name}}" name="{{.Name}}" value="{{value $v .Name}}" {{if .Required}}required{{end}}
                type="{{if eq .Type "NUMBER"}}number{{else if eq .Type "DATE"}}date{{else if eq .Type "TIME"}}time{{else if eq .Type "DATETIME"}}datetime-local{{else}}text{{end}}"
                {{if eq .Type "NUMBER"}}step="any"{{end}}>
            {{end}}
          {{end}}
          {{with index $p .Name}}<div class="problem">{{.}}</div>{{end}}
        {{end}}
        <div class="actions">
          <button class="primary" name="decision" value="SUBMIT">Send</button>
          <button name="decision" value="DECLINE" formnovalidate>Decline to answer</button>
        </div>
      </form>
    {{end}}
    {{if .Expires}}<p class="meta">Expires at <time datetime="{{.Expires}}">{{.Expires}}</time>.</p>{{end}}
  {{end}}
  {{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}
  {{if .Agent}}<p class="meta">Requested by {{.Agent}}.</p>{{end}}
{{end}}
</main>
{{if or .Passkey .Enroll}}
<script>
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
const status = (msg) => { document.getElementById('status').textContent = msg; };
async function post(path, body) {
  const res = await fetch(location.pathname + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : '{}' });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}
async function approve() {
  try {
    status('Waiting for your passkey…');
    const { publicKey } = await post('/passkey/options');
    publicKey.challenge = unb64(publicKey.challenge);
    for (const c of publicKey.allowCredentials || []) c.id = unb64(c.id);
    const cred = await navigator.credentials.get({ publicKey });
    await post('/passkey/verify', {
      id: cred.id, rawId: b64(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: b64(cred.response.clientDataJSON),
        authenticatorData: b64(cred.response.authenticatorData),
        signature: b64(cred.response.signature),
        userHandle: cred.response.userHandle ? b64(cred.response.userHandle) : null,
      },
    });
    location.reload();
  } catch (e) { status(e.message); }
}
async function enroll() {
  try {
    status('Follow your browser’s prompt…');
    const { publicKey } = await post('/options');
    publicKey.challenge = unb64(publicKey.challenge);
    publicKey.user.id = unb64(publicKey.user.id);
    for (const c of publicKey.excludeCredentials || []) c.id = unb64(c.id);
    const cred = await navigator.credentials.create({ publicKey });
    await post('/verify', {
      id: cred.id, rawId: b64(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: b64(cred.response.clientDataJSON),
        attestationObject: b64(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
    });
    status('Passkey created. You can close this page.');
    document.getElementById('enroll').disabled = true;
  } catch (e) { status(e.message); }
}
document.getElementById('approve-passkey')?.addEventListener('click', approve);
document.getElementById('enroll')?.addEventListener('click', enroll);
</script>
{{end}}
</body>
</html>
`))
