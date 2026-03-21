// @gate-project: Gate
// @gate-path: internal/store/storer.go
// Storer defines the Gate persistence interface.
// All DB access goes through this interface — never call sqlite directly from handlers.
package store

import "time"

// IssuedToken is a record of a token Gate has issued.
// Used for revocation tracking only — no sensitive data stored.
type IssuedToken struct {
	JTI       string
	Subject   string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Storer is the Gate persistence interface.
type Storer interface {
	// RecordToken stores metadata for a newly issued token.
	RecordToken(jti, subject string, expiresAt time.Time) error

	// RevokeToken marks a token as revoked by JTI.
	// Returns an error if the JTI does not exist.
	RevokeToken(jti string) error

	// IsRevoked returns true if the given JTI has been revoked.
	// Returns false (not error) if the JTI is unknown — unknown = not revoked.
	IsRevoked(jti string) (bool, error)

	// PruneExpired removes revocation records for tokens past their expiry.
	// Called periodically to bound table growth.
	PruneExpired() error

	// Close releases database resources.
	Close() error
}
