// @gate-project: Gate
// @gate-path: cmd/gate/main.go
// Gate — platform identity authority (ADR-042).
// Startup sequence:
//   1. Load config from environment
//   2. Open SQLite store (~/.nexus/gate.db)
//   3. Load or generate Ed25519 keypair (~/.nexus/gate.key)
//   4. Build issuer + verifier
//   5. Build GitHub OAuth provider (may be unconfigured — degrades gracefully)
//   6. Start prune goroutine (hourly expired token cleanup)
//   7. Start HTTP server on :8088
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	gateapi "github.com/Harshmaury/Gate/internal/api"
	"github.com/Harshmaury/Gate/internal/config"
	"github.com/Harshmaury/Gate/internal/identity"
	"github.com/Harshmaury/Gate/internal/provider"
	"github.com/Harshmaury/Gate/internal/store"
)

func main() {
	logger := log.New(os.Stdout, "[gate] ", log.LstdFlags)
	cfg := config.Load()

	db, err := store.NewSQLiteStore(cfg.DBPath)
	if err != nil {
		logger.Fatalf("open store: %v", err)
	}
	defer db.Close()

	kp, err := identity.LoadOrGenerate(cfg.KeyPath)
	if err != nil {
		logger.Fatalf("load keypair: %v", err)
	}
	logger.Printf("public key loaded (Ed25519)")

	issuer := identity.NewIssuer(kp)
	verifier := identity.NewVerifier(kp)

	gh := provider.NewGitHubProvider(
		cfg.GitHubClientID,
		cfg.GitHubClientSecret,
		cfg.GitHubCallbackURL,
	)
	if cfg.GitHubClientID == "" {
		logger.Printf("WARNING: GATE_GITHUB_CLIENT_ID not set — OAuth login disabled")
	}

	go runPrune(db, logger)

	srv := gateapi.NewServer(gateapi.ServerConfig{
		ServiceToken: cfg.ServiceToken,
		KeyPair:      kp,
		Issuer:       issuer,
		Verifier:     verifier,
		Store:        db,
		GitHub:       gh,
		DeveloperTTL: time.Duration(cfg.DeveloperTTL) * time.Second,
		AgentTTL:     time.Duration(cfg.AgentTTL) * time.Second,
		CITTL:        time.Duration(cfg.CITTL) * time.Second,
		StartTime:    time.Now(),
	})

	srv.Addr = cfg.HTTPAddr
	logger.Printf("listening on %s", cfg.HTTPAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("listen: %v", err)
		}
	}()

	<-stop
	logger.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Printf("shutdown: %v", err)
	}
	logger.Printf("stopped")
}

// runPrune removes expired revocation records hourly.
func runPrune(s store.Storer, logger *log.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		if err := s.PruneExpired(); err != nil {
			logger.Printf("WARNING: prune expired tokens: %v", err)
		}
	}
}
