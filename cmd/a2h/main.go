// Command a2h runs an A2H gateway and talks to one: ask a person for
// approval from a script, send notifications, check a gateway's conformance.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AndreaAcanfora/a2h-gateway/a2h"
	"github.com/AndreaAcanfora/a2h-gateway/channels"
	"github.com/AndreaAcanfora/a2h-gateway/conformance"
	"github.com/AndreaAcanfora/a2h-gateway/gateway"
)

var version = "dev"

const usage = `a2h — Agent-to-Human (A2H) gateway and client

Gateway:
  a2h serve                         run the gateway (configured by environment, see below)
  a2h enroll -principal ID          print a link where a person creates a passkey

Client (A2H_GATEWAY and A2H_API_KEY, or -gateway and -key):
  a2h ask [flags] "question"        ask for approval; exit 0 approved, 1 declined, 2 no answer
  a2h notify [flags] "message"      send an INFORM
  a2h status ID                     print an interaction's status
  a2h conform -to ADDRESS           test a gateway against the A2H spec

Run "a2h <command> -h" for flags. Gateway environment:
  A2H_BASE_URL     public URL people open (required), e.g. https://a2h.example.com
  A2H_LISTEN       listen address (default :8080)
  A2H_DATA_DIR     database and keys (default ./a2h-data)
  A2H_API_KEYS     comma-separated name:key pairs for agents
  A2H_DEV          1: no authentication, http webhooks, console channel (never in production)
  SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM   enable the email channel
  TELEGRAM_BOT_TOKEN                                              enable the telegram channel
  A2H_PUSH         1 to enable the push channel (ntfy); NTFY_TOKEN for protected topics
  A2H_CONSOLE      1 to enable the console channel (links in the log)
`

func main() {
	// Binaries installed with "go install" carry no ldflags; their module
	// version is in the build info.
	if info, ok := debug.ReadBuildInfo(); ok && version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:], stderr)
	case "enroll":
		return cmdEnroll(args[1:], stdout, stderr)
	case "ask":
		return cmdAsk(args[1:], stdout, stderr)
	case "notify":
		return cmdNotify(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	case "conform":
		return cmdConform(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "a2h %s (A2H protocol %s)\n", version, a2h.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "a2h: unknown command %q\n\n%s", args[0], usage)
	return 2
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// gatewayConfig builds the gateway configuration from the environment.
func gatewayConfig(log *slog.Logger) (gateway.Config, error) {
	cfg := gateway.Config{BaseURL: os.Getenv("A2H_BASE_URL"), DataDir: env("A2H_DATA_DIR", "a2h-data"), Logger: log, APIKeys: map[string]string{}}
	if cfg.BaseURL == "" {
		return cfg, errors.New("A2H_BASE_URL is required, e.g. https://a2h.example.com or http://localhost:8080")
	}
	for _, pair := range strings.Split(os.Getenv("A2H_API_KEYS"), ",") {
		if pair = strings.TrimSpace(pair); pair == "" {
			continue
		}
		name, key, ok := strings.Cut(pair, ":")
		if !ok || name == "" || len(key) < 16 {
			return cfg, fmt.Errorf("A2H_API_KEYS: want name:key with keys of at least 16 characters, got %q", name)
		}
		cfg.APIKeys[key] = name
	}
	dev := os.Getenv("A2H_DEV") == "1"
	cfg.NoAuth, cfg.InsecureWebhooks = dev, dev
	if host := os.Getenv("SMTP_HOST"); host != "" {
		port, err := strconv.Atoi(env("SMTP_PORT", "587"))
		if err != nil {
			return cfg, fmt.Errorf("SMTP_PORT: %w", err)
		}
		cfg.Channels = append(cfg.Channels, channels.Email{Host: host, Port: port, Username: os.Getenv("SMTP_USERNAME"), Password: os.Getenv("SMTP_PASSWORD"), From: env("SMTP_FROM", os.Getenv("SMTP_USERNAME"))})
	}
	if token := os.Getenv("TELEGRAM_BOT_TOKEN"); token != "" {
		cfg.Channels = append(cfg.Channels, channels.Telegram{Token: token})
	}
	if os.Getenv("A2H_PUSH") == "1" {
		cfg.Channels = append(cfg.Channels, channels.Ntfy{Token: os.Getenv("NTFY_TOKEN")})
	}
	if dev || os.Getenv("A2H_CONSOLE") == "1" {
		cfg.Channels = append(cfg.Channels, channels.Console{Log: log})
	}
	if len(cfg.Channels) == 0 {
		return cfg, errors.New("no channel configured: set SMTP_HOST, TELEGRAM_BOT_TOKEN, A2H_PUSH=1 or A2H_CONSOLE=1")
	}
	return cfg, nil
}

func cmdServe(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	cfg, err := gatewayConfig(log)
	if err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 2
	}
	if cfg.NoAuth {
		log.Warn("A2H_DEV=1: no authentication and plain-HTTP webhooks. Never expose this gateway to a network.")
	}
	g, err := gateway.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 1
	}
	defer g.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go g.Run(ctx)
	addr := env("A2H_LISTEN", ":8080")
	srv := &http.Server{Addr: addr, Handler: g.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	caps := g.Capabilities()
	log.Info("a2h gateway listening", "addr", addr, "base_url", cfg.BaseURL, "channels", strings.Join(caps.Channels, ","), "version", version)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "a2h:", err)
		return 1
	}
	return 0
}

func cmdEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	principal := fs.String("principal", "", "principal ID, as agents use it in principal_id")
	ttl := fs.Duration("ttl", 24*time.Hour, "validity of the link")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *principal == "" {
		fmt.Fprintln(stderr, "usage: a2h enroll -principal ID")
		return 2
	}
	cfg, err := gatewayConfig(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 2
	}
	g, err := gateway.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 1
	}
	defer g.Close()
	link, err := g.CreateEnrollment(context.Background(), *principal, *ttl)
	if err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 1
	}
	fmt.Fprintf(stderr, "Send this link to %s. It works once and expires in %s:\n", *principal, *ttl)
	fmt.Fprintln(stdout, link)
	return 0
}

type clientFlags struct {
	gateway, key, to, channel, principal, agent string
}

func addClientFlags(fs *flag.FlagSet) *clientFlags {
	c := &clientFlags{}
	fs.StringVar(&c.gateway, "gateway", os.Getenv("A2H_GATEWAY"), "gateway URL (default $A2H_GATEWAY)")
	fs.StringVar(&c.key, "key", os.Getenv("A2H_API_KEY"), "API key (default $A2H_API_KEY)")
	fs.StringVar(&c.to, "to", os.Getenv("A2H_TO"), "where to reach the person: mailto:…, tg:…, https://ntfy.sh/topic (default $A2H_TO)")
	fs.StringVar(&c.channel, "channel", "", "channel type; guessed from -to when empty")
	fs.StringVar(&c.principal, "principal", os.Getenv("A2H_PRINCIPAL"), "principal ID (default $A2H_PRINCIPAL, or derived from -to)")
	fs.StringVar(&c.agent, "agent", env("A2H_AGENT_ID", "a2h-cli"), "agent_id to send")
	return c
}

func (c *clientFlags) check() error {
	if c.gateway == "" {
		return errors.New("no gateway: use -gateway or set A2H_GATEWAY")
	}
	if c.to == "" {
		return errors.New("no recipient: use -to or set A2H_TO")
	}
	if c.channel == "" {
		switch scheme, _, _ := strings.Cut(c.to, ":"); scheme {
		case "mailto":
			c.channel = "email"
		case "tg":
			c.channel = "telegram"
		case "https", "http":
			c.channel = "push"
		case "console":
			c.channel = "console"
		default:
			return fmt.Errorf("cannot guess the channel of %q: use -channel", c.to)
		}
	}
	if c.principal == "" {
		c.principal = "principal-" + c.to
	}
	return nil
}

func (c *clientFlags) message(typ, title, body string) *a2h.Message {
	return &a2h.Message{
		Type: typ, AgentID: c.agent, PrincipalID: c.principal,
		Channel: &a2h.Channel{Type: c.channel, Address: c.to},
		Render:  &a2h.Render{Title: title, Body: body},
	}
}

func cmdAsk(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ask", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := addClientFlags(fs)
	title := fs.String("title", "Approval needed", "title of the request")
	why := fs.String("why", "", "explanation shown to the person")
	ttl := fs.Duration("ttl", 10*time.Minute, "how long to wait for an answer")
	passkey := fs.Bool("passkey", false, "require a passkey to approve (assurance HIGH)")
	jsonOut := fs.Bool("json", false, "print the signed RESPONSE as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, `usage: a2h ask [flags] "question"`)
		return 2
	}
	if err := c.check(); err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 2
	}
	m := c.message(a2h.Authorize, *title, fs.Arg(0))
	m.TTLSec = int(ttl.Seconds())
	if *why != "" {
		m.ExplanationBundle = map[string]any{"why": *why}
	}
	if *passkey {
		m.Assurance = &a2h.Assurance{Level: "HIGH", RequiredFactors: []string{a2h.FactorPasskey}}
	}
	client := a2h.NewClient(c.gateway, c.key)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sent, err := client.Send(ctx, m)
	if err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 3
	}
	fmt.Fprintf(stderr, "Waiting for an answer from %s (interaction %s)…\n", c.to, sent.InteractionID)
	waitCtx, cancel := context.WithTimeout(ctx, *ttl+30*time.Second)
	defer cancel()
	s, err := client.Wait(waitCtx, sent.InteractionID, 2*time.Second)
	if err != nil {
		if ctx.Err() != nil {
			// Interrupted: withdraw the request so that it cannot be approved later.
			client.Cancel(context.Background(), sent.InteractionID)
			fmt.Fprintln(stderr, "a2h: interrupted; request cancelled")
		} else {
			fmt.Fprintln(stderr, "a2h:", err)
		}
		return 3
	}
	if s.State != a2h.StateAnswered {
		msg := strings.ToLower(s.State)
		if s.Error != nil {
			msg += ": " + s.Error.Message
		}
		fmt.Fprintln(stderr, "a2h: no answer:", msg)
		return 2
	}
	resp, err := client.VerifyResponse(ctx, s.Response, m.MessageID)
	if err != nil {
		fmt.Fprintln(stderr, "a2h: the answer failed verification:", err)
		return 3
	}
	if *jsonOut {
		var pretty json.RawMessage = s.Response
		out, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Fprintln(stdout, string(out))
	}
	factor := ""
	if resp.Evidence != nil {
		factor = " (" + resp.Evidence.Factor + ")"
	}
	if resp.Decision == a2h.Approve {
		fmt.Fprintf(stderr, "Approved%s at %s.\n", factor, resp.DecidedAt)
		return 0
	}
	fmt.Fprintf(stderr, "Declined at %s.\n", resp.DecidedAt)
	return 1
}

func cmdNotify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("notify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := addClientFlags(fs)
	title := fs.String("title", "", "title")
	topic := fs.String("topic", "", "params.topic: receipt, progress, alert, result or exception")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, `usage: a2h notify [flags] "message"`)
		return 2
	}
	if err := c.check(); err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 2
	}
	m := c.message(a2h.Inform, *title, fs.Arg(0))
	if *topic != "" {
		m.Params = map[string]any{"topic": *topic}
	}
	r, err := a2h.NewClient(c.gateway, c.key).Send(context.Background(), m)
	if err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 3
	}
	fmt.Fprintln(stdout, r.InteractionID)
	return 0
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || c.gateway == "" {
		fmt.Fprintln(stderr, "usage: a2h status [-gateway URL] ID")
		return 2
	}
	s, err := a2h.NewClient(c.gateway, c.key).Status(context.Background(), fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 3
	}
	out, _ := json.MarshalIndent(s, "", "  ")
	fmt.Fprintln(stdout, string(out))
	return 0
}

func cmdConform(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("conform", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := c.check(); err != nil {
		fmt.Fprintln(stderr, "a2h:", err)
		return 2
	}
	fmt.Fprintf(stderr, "Test intents go to %s and are cancelled right away.\n\n", c.to)
	results := conformance.Run(context.Background(), conformance.Options{BaseURL: c.gateway, APIKey: c.key, Channel: c.channel, Address: c.to})
	for _, r := range results {
		mark := "PASS"
		switch {
		case r.Skipped:
			mark = "SKIP"
		case !r.Passed:
			mark = "FAIL"
		}
		line := fmt.Sprintf("%s  %-6s §%-8s %s", mark, r.Level, r.Section, r.Name)
		if r.Detail != "" {
			line += " (" + r.Detail + ")"
		}
		fmt.Fprintln(stdout, line)
	}
	if !conformance.Passed(results) {
		fmt.Fprintln(stdout, "\nnot conforming: at least one MUST check failed")
		return 1
	}
	fmt.Fprintln(stdout, "\nconforming to the agent-facing API of A2H 1.0")
	return 0
}
