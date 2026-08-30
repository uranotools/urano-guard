# Custom Remote Agent (Bring Your Own Webhook)

Urano Guard works **100% locally** with heuristic inspectors. The remote agent is optional. Use it when you want a second opinion from **your** model, SIEM, or policy service — you do **not** need Urano Cloud.

## When to use a custom webhook

- You cannot send traffic to `agent.urano.cloud` (air-gap, residency, procurement).
- You already have an LLM, rules engine, or SOC pipeline that should score requests.
- You want to attach tenant metadata (`extra`) that Urano Cloud would not know.

Use Urano Cloud only if you already operate that webhook and want the legacy payload.

Runnable local demo (chat API + this webhook): [examples/README.md](examples/README.md).

---

## Minimum setup

```ts
import { createUranoGuard } from '@uranotools/urano-guard';

const guard = createUranoGuard({
    securityMode: 'block_threats',
    remoteAgent: {
        url: 'https://security.internal.example/analyze',
        timeoutMs: 1500,
        failOpen: true,
        invokeWhen: 'local_clean',
        auth: {
            type: 'bearer',
            token: process.env.AGENT_TOKEN
        }
    }
});
```

If the webhook is down, times out, or returns invalid JSON, Guard falls back to **local heuristics** (`failOpen: true` by default). The circuit breaker stops calling a sick endpoint.

---

## What Guard sends (schema 1.0)

`POST` `application/json`:

```json
{
  "schemaVersion": "1.0",
  "source": "urano-guard",
  "requestId": "req_...",
  "request": {
    "ip": "1.2.3.4",
    "senderId": "1.2.3.4",
    "method": "POST",
    "path": "/api/chat",
    "query": {},
    "body": { "message": "..." },
    "headers": { "user-agent": "..." }
  },
  "localAnalysis": {
    "threats": [],
    "maxRiskScore": 0,
    "securityMode": "block_threats"
  },
  "extra": { "app": "checkout", "env": "prod" }
}
```

### Choosing fields (`payload.include`)

| Field | Why send it | Privacy note |
|---|---|---|
| `ip` / `senderId` | Correlation, allow/deny | May be personal data |
| `method` / `path` / `query` | Route context | Query can contain tokens — prefer allowlists |
| `body` / `rawBody` | What the model/WAF must score | Truncated at `maxBodyBytes` (default 32 KB) |
| `headers` | UA / content-type | `Authorization` and `Cookie` are **never** sent unless you put them in `headerAllowlist` |
| `localThreats` | Your agent can see what local regex already found | Useful for `invokeWhen: 'always'` |
| `securityMode` | So the agent can mirror monitor vs block | Safe |
| `fingerprint` | Reserved | Optional |

```ts
remoteAgent: {
    url: process.env.AGENT_URL!,
    payload: {
        include: ['method', 'path', 'body', 'localThreats', 'securityMode'],
        headerAllowlist: ['user-agent', 'content-type'],
        maxBodyBytes: 16_384,
        extra: { app: 'checkout', env: process.env.NODE_ENV }
        // extra: (ctx) => ({ userHint: ctx.senderId })
    }
}
```

Do not put secrets, session cookies, or full `Authorization` headers in `include` unless the agent is in the same trust boundary and you listed them explicitly.

---

## What your agent must return

```json
{
  "verdict": "ALLOW",
  "riskScore": 12,
  "reason": "optional human text",
  "action": "ALLOW",
  "threats": []
}
```

| Field | Rules |
|---|---|
| `verdict` | `ALLOW` \| `BLOCK` \| `MONITOR` \| `QUARANTINE` \| `CRITICAL_THREAT` (alias of BLOCK) |
| `allowed` | If present (boolean), it wins over `verdict` |
| `riskScore` | 0–100. If omitted, derived from verdict |
| `reason` | Shown only when `exposeDecisionDetails: true` |
| `action` | Optional override |
| `threats` | Optional array; Guard creates `REMOTE_AGENT_VERDICT` if you block without it |

HTTP status outside 2xx, timeout, or invalid JSON → Guard treats the call as a **failure** and, with `failOpen: true`, uses the local decision.

A remote `ALLOW` **cannot** override a local `BLOCK` except in `securityMode: 'monitor_only'`.

---

## Authentication

```ts
// Bearer
auth: { type: 'bearer', token: process.env.AGENT_TOKEN }

// Custom header
auth: { type: 'header', headerName: 'X-Api-Key', headerValue: process.env.AGENT_KEY }

// HMAC of the outgoing JSON body (header default x-urano-signature)
auth: { type: 'hmac', hmacSecret: process.env.AGENT_HMAC, hmacHeader: 'x-urano-signature' }

// Verify the agent's response
response: {
    hmacSecret: process.env.AGENT_RESPONSE_HMAC,
    hmacHeader: 'x-urano-signature'
}
```

Legacy aliases still work: `agentWebhookUrl`, `apiKey` (Bearer), `incomingSecret` (outgoing HMAC), `timeoutMs`, `failOpen`.

---

## When the agent is called (`invokeWhen`)

| Mode | Behavior |
|---|---|
| `local_clean` (default) | Call only if local inspectors found nothing. Saves tokens. |
| `local_suspicious` | Call when local `riskScore` is between `minLocalScoreToInvoke` and `maxLocalScoreToInvoke` (default 30–59). |
| `always` | Always (if the circuit is closed). Remote may **raise** the score, not undo a local block. |

---

## Existing agent with a different JSON shape

```ts
remoteAgent: {
    url: 'https://legacy.example/score',
    buildPayload: (ctx, local) => ({
        text: ctx.body,
        hints: local.threats.map(t => t.category)
    }),
    mapResponse: (json: any) => ({
        allowed: json.decision !== 'deny',
        riskScore: json.score ?? 0,
        reason: json.detail
    })
}
```

---

## Example: custom agent server

See [`examples/custom-agent-server.ts`](examples/custom-agent-server.ts). Sketch:

```ts
import express from 'express';

const app = express();
app.use(express.json({ limit: '64kb' }));

app.post('/analyze', (req, res) => {
    const body = JSON.stringify(req.body?.request?.body || '');
    const isThreat = /ignore previous instructions/i.test(body);
    res.json({
        verdict: isThreat ? 'BLOCK' : 'ALLOW',
        riskScore: isThreat ? 88 : 4,
        reason: isThreat ? 'Custom model flagged a jailbreak' : 'ok'
    });
});

app.listen(8787);
```

Point Guard at `http://127.0.0.1:8787/analyze`.

---

## Migrating from `agentWebhookUrl`

```ts
// Before (Urano Cloud legacy shape: { sender, content, path, method })
createUranoGuard({
    agentWebhookUrl: 'https://agent.urano.cloud/webhook',
    apiKey: process.env.URANO_API_KEY
});

// After (same Cloud endpoint, still legacy payload)
createUranoGuard({
    agentWebhookUrl: 'https://agent.urano.cloud/webhook',
    apiKey: process.env.URANO_API_KEY
});

// Custom agent (schema 1.0) — set remoteAgent.payload or buildPayload
createUranoGuard({
    remoteAgent: {
        url: 'https://my-agent.internal/analyze',
        payload: { include: ['path', 'body', 'localThreats'] }
    }
});
```

If **only** `agentWebhookUrl` is set (no `remoteAgent.payload` / `buildPayload`), Guard still sends `{ sender, content, path, method }` so existing Urano Cloud agents keep working.
