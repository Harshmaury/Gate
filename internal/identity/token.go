// @gate-project: Gate
// @gate-path: internal/identity/token.go
// Token handles Ed25519 JWT issuance and local verification.
// This is the correctness core of Gate — all logic here must be tested.
package identity

import (
	"crypto/rand"
	"fmt"
	"time"

	accord "github.com/Harshmaury/Accord/api"
	"github.com/golang-jwt/jwt/v5"
)

const issuer = "gate"

// Claims is the Gate JWT claims structure.
type Claims struct {
	jwt.RegisteredClaims
	Scopes []string `json:"scp"`
}

// Issuer issues signed JWT tokens for the given subject, scopes, and TTL.
type Issuer struct {
	kp *KeyPair
}

// NewIssuer creates a token Issuer backed by the given keypair.
func NewIssuer(kp *KeyPair) *Issuer {
	return &Issuer{kp: kp}
}

// Issue creates and signs a new JWT for the given subject, scopes, and TTL.
// Returns the signed token string and the claim DTO for response construction.
func (i *Issuer) Issue(subject string, scopes []string, ttl time.Duration) (string, *accord.IdentityClaimDTO, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)
	jti, err := newJTI()
	if err != nil {
		return "", nil, fmt.Errorf("issue token: generate jti: %w", err)
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        jti,
		},
		Scopes: scopes,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(i.kp.Private)
	if err != nil {
		return "", nil, fmt.Errorf("issue token: sign: %w", err)
	}
	dto := &accord.IdentityClaimDTO{
		Subject:   subject,
		Scopes:    scopes,
		ExpiresAt: exp.Unix(),
		TokenID:   jti,
	}
	return signed, dto, nil
}

// Verifier verifies JWT tokens using the Gate public key.
// Safe for concurrent use.
type Verifier struct {
	kp *KeyPair
}

// NewVerifier creates a Verifier backed by the given keypair.
func NewVerifier(kp *KeyPair) *Verifier {
	return &Verifier{kp: kp}
}

// Verify parses and validates a signed JWT string.
// Returns the extracted claim on success.
// Does NOT check revocation — callers requiring revocation must check the store separately.
func (v *Verifier) Verify(tokenStr string) (*accord.IdentityClaimDTO, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.kp.Public, nil
	}, jwt.WithIssuer(issuer), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("verify token: invalid")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("verify token: get expiry: %w", err)
	}
	return &accord.IdentityClaimDTO{
		Subject:   claims.Subject,
		Scopes:    claims.Scopes,
		ExpiresAt: exp.Unix(),
		TokenID:   claims.ID,
	}, nil
}

// newJTI generates a random UUID v4 string for use as JWT ID.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
