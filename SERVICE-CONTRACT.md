# SERVICE-CONTRACT.md — Gate
# @version: 1.0.0
# @updated: 2026-03-21

**Service:** `github.com/Harshmaury/Gate`
**Port:** `:8088`
**DB:** `~/.nexus/gate.db`
**Key:** `~/.nexus/gate.key`
**ADR:** ADR-042

---

## Purpose

Gate is the sole identity authority for the platform.
It issues and validates cryptographically signed Ed25519 JWT tokens.
No other service issues or validates identity tokens.

---

## Endpoints

### Public — no authentication required

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| GET | `/gate/public-key` | Ed25519 public key for local token verification |
| POST | `/gate/validate` | Validate a token (signature + expiry + revocation) |
| GET | `/gate/auth/github` | Begin GitHub OAuth flow |
| GET | `/gate/auth/github/callback` | GitHub OAuth callback |

### Protected — requires `X-Service-Token` (ADR-008)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/gate/tokens/agent` | Issue a scoped token for an engxa agent |
| POST | `/gate/tokens/ci` | Issue a scoped token for a CI pipeline |
| POST | `/gate/revoke` | Revoke a token by JTI |

---

## Token model

**Algorithm:** Ed25519 (RFC 8037)
**Format:** JWT (RFC 7519)

**Claims:**
```json
{
  "iss": "gate",
  "sub": "<github_login>@github | agent:<id> | ci:<id>",
  "jti": "<uuid-v4>",
  "iat": 1742567400,
  "exp": 1742653800,
  "scp": ["execute", "observe", "register"]
}
```

**Scope constants** — import from `Canon/identity`, never hardcode:
- `execute` — Forge command submission, project start/stop
- `observe` — read access to events, metrics, history, topology
- `register` — project and service registration
- `admin` — token revocation, key rotation

**Token TTLs (defaults, configurable via env):**
- Developer: 24h (`GATE_DEVELOPER_TTL`)
- Agent: 1h (`GATE_AGENT_TTL`)
- CI pipeline: 15m (`GATE_CI_TTL`)

---

## Validation contract

Services validate tokens in two modes:

**Local validation** (always performed):
- Verify Ed25519 signature against cached public key
- Verify `iss == "gate"`
- Verify `exp` not in the past
- Re-fetch public key from `GET /gate/public-key` if signature fails (handles key rotation)

**Network validation** (Nexus, Forge, Relay, Conduit):
- Call `POST /gate/validate` — adds revocation check
- Returns `{"valid": true, "claim": {...}}` or `{"valid": false, "reason": "..."}`

---

## Header contract

```
X-Identity-Token: <jwt>    — actor identity (ADR-042)
X-Service-Token:  <uuid>   — service mesh token (ADR-008, unchanged)
```

Both are independent. Both may be present. Neither replaces the other.
`X-Identity-Token` is never required on `GET /health`.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GATE_HTTP_ADDR` | `127.0.0.1:8088` | Listen address |
| `GATE_DB_PATH` | `~/.nexus/gate.db` | SQLite database path |
| `GATE_KEY_PATH` | `~/.nexus/gate.key` | Ed25519 private key path |
| `GATE_SERVICE_TOKEN` | — | Required: platform service token (ADR-008) |
| `GATE_GITHUB_CLIENT_ID` | — | GitHub OAuth app client ID |
| `GATE_GITHUB_CLIENT_SECRET` | — | GitHub OAuth app client secret |
| `GATE_GITHUB_CALLBACK_URL` | `http://127.0.0.1:8088/gate/auth/github/callback` | OAuth callback |
| `GATE_DEVELOPER_TTL` | `86400` | Developer token TTL in seconds |
| `GATE_AGENT_TTL` | `3600` | Agent token TTL in seconds |
| `GATE_CI_TTL` | `900` | CI token TTL in seconds |

---

## Invariants — never violate

1. Gate's private key (`gate.key`) never leaves Gate
2. Gate never stores GitHub OAuth tokens, emails, or profile data
3. `GET /health` and `GET /gate/public-key` are always unauthenticated
4. `POST /gate/validate` is always unauthenticated — services must be able to validate without a service token
5. No other service issues identity tokens
6. Scope absence is a hard denial — never silently permit a request missing a required scope
