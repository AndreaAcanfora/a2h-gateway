package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS interactions (
	id             TEXT PRIMARY KEY,
	message_id     TEXT NOT NULL,
	agent          TEXT NOT NULL,
	type           TEXT NOT NULL,
	state          TEXT NOT NULL,
	principal_id   TEXT NOT NULL,
	request        TEXT NOT NULL,
	token_hash     TEXT NOT NULL UNIQUE,
	channel_used   TEXT NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL,
	expires_at     INTEGER NOT NULL DEFAULT 0,
	response       TEXT NOT NULL DEFAULT '',
	error_code     TEXT NOT NULL DEFAULT '',
	error_message  TEXT NOT NULL DEFAULT '',
	webhook_failed INTEGER NOT NULL DEFAULT 0,
	parent_id      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS interactions_waiting ON interactions(state, expires_at);
CREATE INDEX IF NOT EXISTS interactions_parent ON interactions(parent_id);
CREATE TABLE IF NOT EXISTS seen_messages (
	agent          TEXT NOT NULL,
	message_id     TEXT NOT NULL,
	interaction_id TEXT NOT NULL,
	seen_at        INTEGER NOT NULL,
	PRIMARY KEY (agent, message_id)
);
CREATE TABLE IF NOT EXISTS nonces (
	nonce      TEXT PRIMARY KEY,
	expires_at INTEGER NOT NULL,
	used       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS jobs (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	kind           TEXT NOT NULL,
	interaction_id TEXT NOT NULL,
	attempt        INTEGER NOT NULL DEFAULT 1,
	channel_index  INTEGER NOT NULL DEFAULT 0,
	run_at         INTEGER NOT NULL,
	payload        TEXT NOT NULL DEFAULT '',
	delivery_id    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS jobs_due ON jobs(run_at);
CREATE TABLE IF NOT EXISTS principals (
	id         TEXT PRIMARY KEY,
	handle     BLOB NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
	id           BLOB PRIMARY KEY,
	principal_id TEXT NOT NULL,
	data         TEXT NOT NULL,
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollments (
	token_hash   TEXT PRIMARY KEY,
	principal_id TEXT NOT NULL,
	expires_at   INTEGER NOT NULL,
	used         INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pairings (
	token_hash   TEXT PRIMARY KEY,
	principal_id TEXT NOT NULL,
	expires_at   INTEGER NOT NULL,
	used         INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
	id           TEXT PRIMARY KEY,
	principal_id TEXT NOT NULL,
	name         TEXT NOT NULL,
	public_key   TEXT NOT NULL,
	token_hash   TEXT NOT NULL UNIQUE,
	push_url     TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_principal ON devices(principal_id);
CREATE INDEX IF NOT EXISTS interactions_principal ON interactions(principal_id, created_at);
CREATE TABLE IF NOT EXISTS sessions (
	key        TEXT PRIMARY KEY,
	data       TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
`

// Store is the gateway's persistent state, in SQLite.
type Store struct{ db *sql.DB }

// OpenStore opens (and creates) the database at path. ":memory:" works for tests.
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	if path == ":memory:" {
		// A named in-memory database per store: with an unnamed shared cache,
		// every store in the process would share one database.
		dsn = "file:mem-" + randomToken() + "?mode=memory&cache=shared&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		// One connection, or each would see its own empty database.
		db.SetMaxOpenConns(1)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

// interaction is one stored intent.
type interaction struct {
	ID, MessageID, Agent, Type, State, PrincipalID string
	Request                                        []byte
	TokenHash, ChannelUsed                         string
	CreatedAt, UpdatedAt, ExpiresAt                time.Time
	Response                                       []byte
	ErrorCode, ErrorMessage                        string
	WebhookFailed                                  bool
	ParentID                                       string
}

const interactionCols = `id, message_id, agent, type, state, principal_id, request, token_hash, channel_used, created_at, updated_at, expires_at, response, error_code, error_message, webhook_failed, parent_id`

func scanInteraction(row interface{ Scan(...any) error }) (*interaction, error) {
	var i interaction
	var req, resp string
	var created, updated, expires int64
	var wf int
	err := row.Scan(&i.ID, &i.MessageID, &i.Agent, &i.Type, &i.State, &i.PrincipalID, &req, &i.TokenHash, &i.ChannelUsed,
		&created, &updated, &expires, &resp, &i.ErrorCode, &i.ErrorMessage, &wf, &i.ParentID)
	if err != nil {
		return nil, err
	}
	i.Request, i.Response = []byte(req), []byte(resp)
	i.CreatedAt, i.UpdatedAt, i.ExpiresAt = fromMS(created), fromMS(updated), fromMS(expires)
	i.WebhookFailed = wf != 0
	return &i, nil
}

var errNotFound = errors.New("not found")

func (s *Store) getInteraction(ctx context.Context, where string, arg any) (*interaction, error) {
	i, err := scanInteraction(s.db.QueryRowContext(ctx, `SELECT `+interactionCols+` FROM interactions WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return i, err
}

func (s *Store) insertInteraction(ctx context.Context, tx *sql.Tx, i *interaction) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO interactions (`+interactionCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		i.ID, i.MessageID, i.Agent, i.Type, i.State, i.PrincipalID, string(i.Request), i.TokenHash, i.ChannelUsed,
		ms(i.CreatedAt), ms(i.UpdatedAt), ms(i.ExpiresAt), string(i.Response), i.ErrorCode, i.ErrorMessage, 0, i.ParentID)
	return err
}

// job is a scheduled delivery or webhook.
type job struct {
	ID            int64
	Kind          string // "deliver" or "webhook"
	InteractionID string
	Attempt       int
	ChannelIndex  int
	RunAt         time.Time
	Payload       []byte
	DeliveryID    string
}

func (s *Store) addJob(ctx context.Context, ex interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, j job) error {
	_, err := ex.ExecContext(ctx, `INSERT INTO jobs (kind, interaction_id, attempt, channel_index, run_at, payload, delivery_id) VALUES (?,?,?,?,?,?,?)`,
		j.Kind, j.InteractionID, j.Attempt, j.ChannelIndex, ms(j.RunAt), string(j.Payload), j.DeliveryID)
	return err
}

// takeDueJobs removes and returns the jobs due at now.
func (s *Store) takeDueJobs(ctx context.Context, now time.Time, limit int) ([]job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id, kind, interaction_id, attempt, channel_index, run_at, payload, delivery_id FROM jobs WHERE run_at <= ? ORDER BY run_at, id LIMIT ?`, ms(now), limit)
	if err != nil {
		return nil, err
	}
	var jobs []job
	for rows.Next() {
		var j job
		var runAt int64
		var payload string
		if err := rows.Scan(&j.ID, &j.Kind, &j.InteractionID, &j.Attempt, &j.ChannelIndex, &runAt, &payload, &j.DeliveryID); err != nil {
			rows.Close()
			return nil, err
		}
		j.RunAt, j.Payload = fromMS(runAt), []byte(payload)
		jobs = append(jobs, j)
	}
	rows.Close()
	for _, j := range jobs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE id = ?`, j.ID); err != nil {
			return nil, err
		}
	}
	return jobs, tx.Commit()
}

func (s *Store) putSession(ctx context.Context, key string, data []byte, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (key, data, expires_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at`, key, string(data), ms(expires))
	return err
}

// takeSession returns and deletes a session that has not expired.
func (s *Store) takeSession(ctx context.Context, key string, now time.Time) ([]byte, error) {
	var data string
	var expires int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM sessions WHERE key = ? RETURNING data, expires_at`, key).Scan(&data, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && expires < ms(now)) {
		return nil, errNotFound
	}
	return []byte(data), err
}

// cleanup deletes expired bookkeeping rows.
func (s *Store) cleanup(ctx context.Context, now time.Time, idempotencyWindow time.Duration) error {
	stmts := []struct {
		q   string
		arg int64
	}{
		{`DELETE FROM seen_messages WHERE seen_at < ?`, ms(now.Add(-idempotencyWindow))},
		{`DELETE FROM nonces WHERE expires_at < ?`, ms(now.Add(-time.Hour))},
		{`DELETE FROM sessions WHERE expires_at < ?`, ms(now)},
		{`DELETE FROM enrollments WHERE expires_at < ?`, ms(now.Add(-24 * time.Hour))},
		{`DELETE FROM pairings WHERE expires_at < ?`, ms(now.Add(-24 * time.Hour))},
	}
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st.q, st.arg); err != nil {
			return err
		}
	}
	return nil
}
