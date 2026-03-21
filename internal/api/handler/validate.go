// @gate-project: Gate
// @gate-path: internal/api/handler/validate.go
package handler

import (
	"encoding/json"
	"net/http"

	accord "github.com/Harshmaury/Accord/api"
	"github.com/Harshmaury/Gate/internal/identity"
	"github.com/Harshmaury/Gate/internal/store"
)

// ValidateHandler serves POST /gate/validate.
type ValidateHandler struct {
	verifier *identity.Verifier
	store    store.Storer
}

// NewValidateHandler creates a ValidateHandler.
func NewValidateHandler(v *identity.Verifier, s store.Storer) *ValidateHandler {
	return &ValidateHandler{verifier: v, store: s}
}

// ServeHTTP handles POST /gate/validate.
// Performs local signature + expiry verification, then checks revocation.
func (h *ValidateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req accord.GateValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondOK(w, accord.GateValidateResponse{Valid: false, Reason: "invalid request body"})
		return
	}
	if req.Token == "" {
		respondOK(w, accord.GateValidateResponse{Valid: false, Reason: "token required"})
		return
	}
	claim, err := h.verifier.Verify(req.Token)
	if err != nil {
		respondOK(w, accord.GateValidateResponse{Valid: false, Reason: err.Error()})
		return
	}
	revoked, err := h.store.IsRevoked(claim.TokenID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "revocation check failed")
		return
	}
	if revoked {
		respondOK(w, accord.GateValidateResponse{Valid: false, Reason: "token revoked"})
		return
	}
	respondOK(w, accord.GateValidateResponse{Valid: true, Claim: claim})
}
