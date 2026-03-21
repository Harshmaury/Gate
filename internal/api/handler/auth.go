// @gate-project: Gate
// @gate-path: internal/api/handler/auth.go
package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	accord "github.com/Harshmaury/Accord/api"
	canon "github.com/Harshmaury/Canon/identity"
	"github.com/Harshmaury/Gate/internal/identity"
	"github.com/Harshmaury/Gate/internal/provider"
	"github.com/Harshmaury/Gate/internal/store"
)

// AuthHandler serves the GitHub OAuth flow.
type AuthHandler struct {
	github       *provider.GitHubProvider
	issuer       *identity.Issuer
	store        store.Storer
	developerTTL time.Duration

	mu     sync.Mutex
	states map[string]time.Time // state → issued_at (for CSRF protection)
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(
	gh *provider.GitHubProvider,
	iss *identity.Issuer,
	s store.Storer,
	developerTTL time.Duration,
) *AuthHandler {
	return &AuthHandler{
		github:       gh,
		issuer:       iss,
		store:        s,
		developerTTL: developerTTL,
		states:       make(map[string]time.Time),
	}
}

// GitHub handles GET /gate/auth/github — redirects to GitHub OAuth consent.
func (h *AuthHandler) GitHub(w http.ResponseWriter, r *http.Request) {
	state, err := newState()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "state generation failed")
		return
	}
	h.mu.Lock()
	h.states[state] = time.Now()
	h.mu.Unlock()
	http.Redirect(w, r, h.github.AuthURL(state), http.StatusFound)
}

// GitHubCallback handles GET /gate/auth/github/callback.
func (h *AuthHandler) GitHubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if !h.consumeState(state) {
		respondErr(w, http.StatusBadRequest, "invalid or expired oauth state")
		return
	}
	if code == "" {
		respondErr(w, http.StatusBadRequest, "code required")
		return
	}

	subject, err := h.github.Exchange(r.Context(), code)
	if err != nil {
		respondErr(w, http.StatusBadGateway, "github oauth failed")
		return
	}

	scopes := []string{
		canon.ScopeExecute,
		canon.ScopeObserve,
		canon.ScopeRegister,
	}
	signed, dto, err := h.issuer.Issue(subject, scopes, h.developerTTL)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "token issuance failed")
		return
	}
	if err := h.store.RecordToken(dto.TokenID, subject, time.Unix(dto.ExpiresAt, 0)); err != nil {
		respondErr(w, http.StatusInternalServerError, "token record failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(accord.GateTokenResponse{ //nolint:errcheck
		Token:     signed,
		Subject:   subject,
		ExpiresAt: dto.ExpiresAt,
	})
}

// consumeState validates and removes a state value (one-time use, 10min window).
func (h *AuthHandler) consumeState(state string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	issuedAt, ok := h.states[state]
	if !ok {
		return false
	}
	delete(h.states, state)
	return time.Since(issuedAt) < 10*time.Minute
}

func newState() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b[:]), nil
}
