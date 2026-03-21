// @gate-project: Gate
// @gate-path: internal/api/handler/publickey.go
package handler

import (
	"net/http"

	accord "github.com/Harshmaury/Accord/api"
	"github.com/Harshmaury/Gate/internal/identity"
)

// PublicKeyHandler serves GET /gate/public-key.
type PublicKeyHandler struct {
	kp *identity.KeyPair
}

// NewPublicKeyHandler creates a PublicKeyHandler.
func NewPublicKeyHandler(kp *identity.KeyPair) *PublicKeyHandler {
	return &PublicKeyHandler{kp: kp}
}

// ServeHTTP handles GET /gate/public-key.
// No authentication required — this endpoint is called by all services at startup.
func (h *PublicKeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	respondOK(w, accord.GatePublicKeyDTO{
		Key: h.kp.PublicKeyBase64(),
		Alg: "Ed25519",
	})
}
