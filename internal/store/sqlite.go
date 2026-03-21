// @gate-project: Gate
// @gate-path: internal/store/sqlite.go
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS issued_tokens (
	jti        TEXT PRIMARY KEY,
	subject    TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_issued_tokens_expires ON issued_tokens(expires_at);
`

// SQLiteStore is the SQLite-backed Storer implementation.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) the Gate database at path.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	expanded := expandHome(path)
	if err := os.MkdirAll(filepath.Dir(expanded), 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := sql.Open("sqlite3", expanded+"?_journal=WAL&_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open gate db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) RecordToken(jti, subject string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO issued_tokens (jti, subject, expires_at) VALUES (?, ?, ?)`,
		jti, subject, expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("record token: %w", err)
	}
	return nil
}

func (s *SQLiteStore) RevokeToken(jti string) error {
	res, err := s.db.Exec(
		`UPDATE issued_tokens SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL`,
		time.Now().Unix(), jti,
	)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke token rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("token not found or already revoked: %s", jti)
	}
	return nil
}

func (s *SQLiteStore) IsRevoked(jti string) (bool, error) {
	var revokedAt sql.NullInt64
	err := s.db.QueryRow(
		`SELECT revoked_at FROM issued_tokens WHERE jti = ?`, jti,
	).Scan(&revokedAt)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check revoked: %w", err)
	}
	return revokedAt.Valid, nil
}

func (s *SQLiteStore) PruneExpired() error {
	_, err := s.db.Exec(
		`DELETE FROM issued_tokens WHERE expires_at < ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("prune expired: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func expandHome(path string) string {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
