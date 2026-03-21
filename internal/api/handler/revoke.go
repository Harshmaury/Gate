// @gate-project: Gate
// @gate-path: internal/api/handler/revoke.go
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/Harshmaury/Gate/internal/store"
)

// RevokeHandler serves POST /gate/revoke.
// Requires admin scope — enforced by middleware before this handler runs.
type RevokeHandler struct {
	store store.Storer
}

// NewRevokeHandler creates a RevokeHandler.
func NewRevokeHandler(s store.Storer) *RevokeHandler {
	return &RevokeHandler{store: s}
}

// ServeHTTP handles POST /gate/revoke.
func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JTI string `json:"jti"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.JTI == "" {
		respondErr(w, http.StatusBadRequest, "jti required")
		return
	}
	if err := h.store.RevokeToken(req.JTI); err != nil {
		respondErr(w, http.StatusNotFound, err.Error())
		return
	}
	respondOK(w, map[string]string{"jti": req.JTI, "status": "revoked"})
}
