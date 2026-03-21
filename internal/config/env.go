// @gate-project: Gate
// @gate-path: internal/config/env.go
package config

import "os"

const (
	defaultHTTPAddr  = "127.0.0.1:8088"
	defaultDBPath    = "~/.nexus/gate.db"
	defaultKeyPath   = "~/.nexus/gate.key"
	defaultTokenTTL  = "86400"  // 24h in seconds — developer default
	defaultAgentTTL  = "3600"   // 1h
	defaultCITTL     = "900"    // 15m
)

// Config holds all Gate runtime configuration.
type Config struct {
	HTTPAddr         string
	DBPath           string
	KeyPath          string
	ServiceToken     string
	GitHubClientID   string
	GitHubClientSecret string
	GitHubCallbackURL  string
	DeveloperTTL     int
	AgentTTL         int
	CITTL            int
}

// Load reads Gate configuration from environment variables.
func Load() *Config {
	return &Config{
		HTTPAddr:           EnvOrDefault("GATE_HTTP_ADDR", defaultHTTPAddr),
		DBPath:             EnvOrDefault("GATE_DB_PATH", defaultDBPath),
		KeyPath:            EnvOrDefault("GATE_KEY_PATH", defaultKeyPath),
		ServiceToken:       os.Getenv("GATE_SERVICE_TOKEN"),
		GitHubClientID:     os.Getenv("GATE_GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GATE_GITHUB_CLIENT_SECRET"),
		GitHubCallbackURL:  EnvOrDefault("GATE_GITHUB_CALLBACK_URL", "http://127.0.0.1:8088/gate/auth/github/callback"),
		DeveloperTTL:       envInt("GATE_DEVELOPER_TTL", defaultTokenTTL),
		AgentTTL:           envInt("GATE_AGENT_TTL", defaultAgentTTL),
		CITTL:              envInt("GATE_CI_TTL", defaultCITTL),
	}
}

// EnvOrDefault returns the env var value or the default if unset.
func EnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key, def string) int {
	v := EnvOrDefault(key, def)
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 86400
		}
		n = n*10 + int(c-'0')
	}
	return n
}
