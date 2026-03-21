// @gate-project: Gate
// @gate-path: internal/api/handler/tokens.go
package handler

import (
	"encoding/json"
	"net/http"
	"time"

	accord "github.com/Harshmaury/Accord/api"
	canon "github.com/Harshmaury/Canon/identity"
	"github.com/Harshmaury/Gate/internal/identity"
	"github.com/Harshmaury/Gate/internal/store"
)

// TokensHandler serves POST /gate/tokens/agent and POST /gate/tokens/ci.
type TokensHandler struct {
	issuer   *identity.Issuer
	store    store.Storer
	agentTTL time.Duration
	ciTTL    time.Duration
}

// NewTokensHandler creates a TokensHandler.
func NewTokensHandler(iss *identity.Issuer, s store.Storer, agentTTL, ciTTL time.Duration) *TokensHandler {
	return &TokensHandler{issuer: iss, store: s, agentTTL: agentTTL, ciTTL: ciTTL}
}

// AgentToken handles POST /gate/tokens/agent.
// Called by engxa to obtain a scoped identity token.
// Requires X-Service-Token (agent is a known platform component — ADR-008).
func (h *TokensHandler) AgentToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" {
		respondErr(w, http.StatusBadRequest, "agent_id required")
		return
	}
	subject := "agent:" + req.AgentID
	scopes := []string{canon.ScopeExecute, canon.ScopeObserve}
	h.issueAndRespond(w, subject, scopes, h.agentTTL)
}

// CIToken handles POST /gate/tokens/ci.
// Called by CI pipelines to obtain a scoped identity token.
// Requires X-Service-Token.
func (h *TokensHandler) CIToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PipelineID string `json:"pipeline_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PipelineID == "" {
		respondErr(w, http.StatusBadRequest, "pipeline_id required")
		return
	}
	subject := "ci:" + req.PipelineID
	scopes := []string{canon.ScopeExecute, canon.ScopeObserve}
	h.issueAndRespond(w, subject, scopes, h.ciTTL)
}

func (h *TokensHandler) issueAndRespond(w http.ResponseWriter, subject string, scopes []string, ttl time.Duration) {
	signed, dto, err := h.issuer.Issue(subject, scopes, ttl)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "token issuance failed")
		return
	}
	if err := h.store.RecordToken(dto.TokenID, subject, time.Unix(dto.ExpiresAt, 0)); err != nil {
		respondErr(w, http.StatusInternalServerError, "token record failed")
		return
	}
	respondOK(w, accord.GateTokenResponse{
		Token:     signed,
		Subject:   subject,
		ExpiresAt: dto.ExpiresAt,
	})
}
