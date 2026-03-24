// @gate-project: gate
// @gate-path: SERVICE-CONTRACT.md
# SERVICE-CONTRACT.md — Gate
# @version: 1.0.0
# @updated: 2026-03-25

**Port:** 8088 · **DB:** `~/.nexus/gate.db` · **Key:** `~/.nexus/gate.key` · **Domain:** Control

---

## Code

```
cmd/gate/main.go                startup, key load/gen
internal/identity/token.go      Ed25519 JWT issue + local validation
internal/identity/keypair.go    key generation, persistence
internal/store/sqlite.go        revocation list, token records
internal/api/handler/auth.go    GitHub OAuth flow
internal/api/handler/tokens.go  POST /gate/tokens/*
internal/api/handler/validate.go POST /gate/validate
internal/api/handler/revoke.go  POST /gate/revoke
internal/provider/github.go     GitHub OAuth exchange
```

---

## Contract

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Liveness |
| GET | `/gate/public-key` | none | `{key: base64-DER, alg: "Ed25519"}` |
| POST | `/gate/validate` | none | `{token}` → `{valid, claim}` or `{valid:false, reason}` |
| GET | `/gate/auth/github` | none | Begin OAuth |
| GET | `/gate/auth/github/callback` | none | OAuth callback → token |
| POST | `/gate/tokens/agent` | service token | Issue agent token |
| POST | `/gate/tokens/ci` | service token | Issue CI token |
| POST | `/gate/revoke` | service token | Revoke by JTI |

### Token claims

```json
{"iss":"gate","sub":"<login>@github|agent:<id>|ci:<id>","jti":"<uuid>","iat":N,"exp":N,"scp":["execute|observe|register|admin"]}
```

Scope constants: `Canon/identity.ScopeExecute`, `ScopeObserve`, `ScopeRegister`, `ScopeAdmin`, `ScopeTunnel`.

### TTLs (env-configurable)

`GATE_DEVELOPER_TTL` 86400s · `GATE_AGENT_TTL` 3600s · `GATE_CI_TTL` 900s

---

## Control

**Key lifecycle:** load from `GATE_KEY_PATH` at startup; generate if absent.

**Validation modes:**
- Local (all services): verify Ed25519 signature + `iss` + `exp`. Re-fetch public key on signature failure (handles rotation).
- Network (Nexus, Forge, Relay, Conduit): `POST /gate/validate` adds revocation check.

**Invariants:**
1. Private key never leaves Gate
2. GitHub tokens, emails, profiles never stored
3. `/health` and `/gate/public-key` always unauthenticated
4. `/gate/validate` always unauthenticated
5. No other service issues identity tokens
6. Scope absence is a hard denial — no silent permit

---

## Context

Sole identity authority on the platform. `X-Identity-Token` is independent from `X-Service-Token` — both may be present simultaneously, neither replaces the other.
