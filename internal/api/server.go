// @gate-project: Gate
// @gate-path: internal/api/server.go
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Harshmaury/Gate/internal/api/handler"
	"github.com/Harshmaury/Gate/internal/api/middleware"
	"github.com/Harshmaury/Gate/internal/identity"
	"github.com/Harshmaury/Gate/internal/provider"
	"github.com/Harshmaury/Gate/internal/store"
)

// ServerConfig holds all dependencies the HTTP server needs.
type ServerConfig struct {
	ServiceToken string
	KeyPair      *identity.KeyPair
	Issuer       *identity.Issuer
	Verifier     *identity.Verifier
	Store        store.Storer
	GitHub       *provider.GitHubProvider
	DeveloperTTL time.Duration
	AgentTTL     time.Duration
	CITTL        time.Duration
	StartTime    time.Time
}

// NewServer builds and returns the Gate HTTP server.
func NewServer(cfg ServerConfig) *http.Server {
	mux := http.NewServeMux()
	requireService := middleware.ServiceAuth(cfg.ServiceToken)

	// ── public endpoints (no auth) ────────────────────────────────────────────
	mux.HandleFunc("GET /health", makeHealthHandler(cfg.StartTime))
	mux.Handle("GET /gate/public-key", handler.NewPublicKeyHandler(cfg.KeyPair))
	mux.Handle("POST /gate/validate", handler.NewValidateHandler(cfg.Verifier, cfg.Store))

	// ── OAuth flow (no service token — browser redirects) ─────────────────────
	authH := handler.NewAuthHandler(cfg.GitHub, cfg.Issuer, cfg.Store, cfg.DeveloperTTL)
	mux.HandleFunc("GET /gate/auth/github", authH.GitHub)
	mux.HandleFunc("GET /gate/auth/github/callback", authH.GitHubCallback)
	mux.HandleFunc("GET /gate/auth/poll", authH.Poll)

	// ── service-token protected endpoints ─────────────────────────────────────
	tokensH := handler.NewTokensHandler(cfg.Issuer, cfg.Store, cfg.AgentTTL, cfg.CITTL)
	mux.Handle("POST /gate/tokens/agent",
		requireService(http.HandlerFunc(tokensH.AgentToken)))
	mux.Handle("POST /gate/tokens/ci",
		requireService(http.HandlerFunc(tokensH.CIToken)))
	mux.Handle("POST /gate/revoke",
		requireService(handler.NewRevokeHandler(cfg.Store)))

	return &http.Server{
		Addr:         ":8088",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func makeHealthHandler(startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"ok":             true,
			"status":         "ok",
			"uptime_seconds": time.Since(startTime).Seconds(),
			"service":        "gate",
		})
	}
}
