// @gate-project: Gate
// @gate-path: internal/api/middleware/service_auth.go
// ServiceAuth enforces ADR-008 X-Service-Token on protected routes.
// Applied to token issuance and revoke endpoints — not to /gate/validate,
// /gate/public-key, /gate/auth/*, or /health.
package middleware

import (
	"crypto/subtle"
	"net/http"

	canon "github.com/Harshmaury/Canon/identity"
)

// ServiceAuth returns middleware that enforces the platform service token.
func ServiceAuth(serviceToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get(canon.ServiceTokenHeader)
			if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"ok":false,"error":"unauthorized"}`)) //nolint:errcheck
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
