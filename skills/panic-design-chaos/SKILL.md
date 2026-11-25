---
name: panic-design-chaos
description: Simulate network degradation, HTTP errors (502, 504, 429, 444), latency, jitter, and packet loss against any target upstream service using Panic Design Cloud Gateway.
---

# Panic Design Chaos Engineering Agent Skill

This skill enables AI coding agents (Codex, Muse, Cursor, Antigravity, Claude Code) to simulate real-world distributed network faults during code development, unit testing, and resilience evaluation.

---

## 1. Prerequisites

Obtain your Developer API Key from the Panic Design web interface:
1. Log in via GitHub at [panic.andrewwangdev.com](https://panic.andrewwangdev.com).
2. Open the user dropdown menu in the top right corner.
3. Click **Developer API Key** -> **Generate Key**.
4. Set the key in your agent's environment:
   ```bash
   export PANIC_DESIGN_API_KEY="pd_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
   ```

---

## 2. Agent Workflow

```
[ AI Agent / Codex ]
        │
        ▼ 1. POST /api/v1/chaos/tokens (Bearer $PANIC_DESIGN_API_KEY)
[ Control Plane: panic.andrewwangdev.com ] ──► Returns signed JWT & tokenId
        │
        ▼ 2. HTTP Request with Header 'X-Chaos-Token: <jwt>'
[ Data Plane: gateway.andrewwangdev.com ]
        │
        ▼ 3. Edge Worker intercepts & executes simulated chaos (502, 504, latency, etc.)
[ Target Upstream Server ]
```

---

## 3. Endpoints Specification

### A. Mint a Chaos Token
- **Endpoint**: `POST https://panic.andrewwangdev.com/api/v1/chaos/tokens`
- **Headers**:
  - `Authorization: Bearer $PANIC_DESIGN_API_KEY`
  - `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "targetHost": "api.example.com",
    "fault": "502",
    "latency": 0,
    "customTtl": 0.25
  }
  ```
- **Supported Parameters**:
  - `targetHost` *(string, required)*: Fully qualified domain name or public IP of your upstream service.
  - `fault` *(string, required)*: `'502'` | `'504'` | `'429'` | `'444'` | `'latency'`.
  - `latency` *(number, optional)*: Injected delay in ms (0-10000, required if fault is latency).
  - `jitter` *(number, optional)*: Fluctuating variance in ms (0-10000).
  - `packetLoss` *(number, optional)*: Drop rate percentage (0-100).
  - `distribution` *(string, optional)*: `'Uniform'` | `'Normal'` | `'Spikes'`.
  - `mutilationStrategy` *(string, optional)*: `'None'` | `'Unexpected EOF'` | `'Type Poisoning'` | `'Empty Shell'`.
  - `customTtl` *(number, optional)*: Token expiration in hours (0.05 to 2 hours, default 0.25h).

- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "tokenId": "cly1234567890",
    "tokenHint": "eyJhbGci...9qu4",
    "jwtToken": "eyJhbGciOiJIUzI1NiIs...",
    "gatewayUrl": "https://gateway.andrewwangdev.com",
    "expiresAt": "2026-11-16T16:30:00.000Z",
    "activeTokensCount": 1,
    "remainingActiveSlots": 4
  }
  ```

---

### B. Execute Fault Injection via Data Plane
Send your HTTP traffic to the Panic Design Data Plane with the `X-Chaos-Token` header:
```bash
curl -i -H "X-Chaos-Token: $JWT_TOKEN" "https://gateway.andrewwangdev.com/v1/checkout"
```
Or via query parameter:
```bash
curl -i "https://gateway.andrewwangdev.com/v1/checkout?token=$JWT_TOKEN"
```

---

### C. Revoke a Chaos Token
When testing completes or when you need to free up an active slot:
- **Endpoint**: `DELETE https://panic.andrewwangdev.com/api/v1/chaos/tokens/:id`
- **Headers**: `Authorization: Bearer $PANIC_DESIGN_API_KEY`
- **Response**:
  ```json
  {
    "success": true,
    "message": "Token revoked successfully.",
    "tokenId": "cly1234567890"
  }
  ```

---

### D. List Active Tokens
- **Endpoint**: `GET https://panic.andrewwangdev.com/api/v1/chaos/tokens`
- **Headers**: `Authorization: Bearer $PANIC_DESIGN_API_KEY`

---

## 4. Agent Error Handling & Best Practices

1. **403 CONCURRENT_CAP_EXCEEDED**:
   - Accounts have a maximum of 5 concurrent active tokens.
   - If this error is returned, call `GET /api/v1/chaos/tokens` to list active tokens, then call `DELETE /api/v1/chaos/tokens/:id` on older tokens before minting a new one.
2. **400 SSRF_DETECTED**:
   - Panic Design enforces dual-stack (A + AAAA) private network protection. Loopback addresses (`127.0.0.1`, `::1`), link-local (`169.254.169.254`), and internal subnets are blocked.
3. **Audit Visibility**:
   - Every token minted or revoked by your agent is recorded under `[AGENT]` source and visible in real time on the [Audit Logs Console](https://panic.andrewwangdev.com/logs).
