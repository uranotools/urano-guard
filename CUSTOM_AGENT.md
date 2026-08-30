# Security agent — connect analysis anywhere

Urano Guard is two layers:

1. **Local WAF** — regex + normalization in your Node process. Evolves independently (inspectors, store, adapters).
2. **Agent** — a service *you* run (or already have). Guard POSTs a JSON envelope to any HTTPS URL. The agent scores the request, and can return **analysis** and a **report**. Guard does not host the model and does not write the report; it forwards what you return on `SecurityDecision`.

The WAF works with the agent **off**. You do **not** need Urano to start.

## Who owns the agent

This SDK **integrates** an agent; it does **not** ship one.

| You choose | Who is responsible |
|---|---|
| `remoteAgent.url` = your server | **You**: uptime, model, prompts, logs the skill returns, reports, residency |
| `remoteAgent.url` = Urano infrastructure | **Urano**: that endpoint. Guard still only sends what you declared (`include` / `onRequest` / `skills`) |
| No `url` | Local WAF only. No agent hop |

A stolen agent token can see follow-up bodies and skill results. Treat the agent host as a trust boundary. Do not declare skills that dump secrets.

## What the agent is for

| Job | Who does it |
|---|---|
| Cheap, obvious blocks (SQLi, jailbreak strings, padding) | Local WAF |
| Ambiguous / novel phrasing, tenant policy, LLM-in-the-loop | **Your agent** |
| Narrative for humans (`analysis`) | **Your agent** |
| Structured report (ticket, markdown, findings) | **Your agent** → `decision.agentReport` |
| Slack / Jira / SIEM after the fact | Your code reading `agentReport` (or `createHttpAuditSink` for the safe audit line only) |

Runnable demo (chat API + sample agent): [examples/README.md](examples/README.md).

Legacy `agentWebhookUrl` → `agent.urano.cloud` still sends the old `{ sender, content, path, method }` shape if you do not set `remoteAgent.payload`.

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

## Ask for more only if needed (declared disclose)

Send a **small first hop**. If the agent cannot decide, it asks for extra fields. Guard sends a **single** follow-up with the intersection of `need` and `payload.onRequest`. Anything else is dropped (`denied` on the follow-up). No `onRequest` = no second hop.

```ts
remoteAgent: {
    url: process.env.AGENT_URL!,
    payload: {
        include: ['method', 'path', 'localThreats'], // first POST
        onRequest: ['body', 'headers'],              // agent may NEED these
        headerAllowlist: ['user-agent', 'content-type'],
        maxBodyBytes: 16_384
    },
    // extras the agent is allowed to put on SecurityDecision
    response: {
        include: ['reason', 'analysis', 'report'] // omit = all extras; [] = verdict only
    }
}
```

First envelope includes `capabilities.canDisclose` so the agent knows what it may ask for.

```json
{
  "verdict": "NEED",
  "need": ["body"]
}
```

(`need`, `requestFields`, or `disclose`. `verdict` must be `NEED` or omitted.)

Follow-up (same `requestId`, `followUp: true`) adds only granted fields. A second `NEED` is a failure (fail-open / fail-closed). `timeoutMs` is a **budget for both hops**.

`buildPayload` / legacy `{ sender, content }` do not get this dance — those shapes already send whatever you built.

---

## Declared extras and mini-skills (logs, chunks)

**Always-on custom vars** — `payload.extra` (object or `(ctx) => …`) goes on every hop. Use for tenant id, env, app name. Do not put full logs here.

**On-demand skills** — you declare a catalog. The agent may invoke those names on a NEED hop. Guard calls *your* `provide` and sends the result on the follow-up. Guard does **not** read your log files; a “full log” or “chunk” skill is your integration.

```ts
remoteAgent: {
    url: process.env.AGENT_URL!,
    payload: {
        include: ['method', 'path'],
        onRequest: ['body'],
        extra: { app: 'checkout', env: process.env.NODE_ENV }
    },
    skills: {
        maxResultBytes: 16_384,
        catalog: {
            'logs.recent': {
                description: 'Last N app log lines (not Guard audit)',
                provide: async (args, ctx) => appLogs.tail(ctx.path, Number(args?.limit ?? 40))
            },
            'logs.chunk': {
                description: 'Paginated logs — agent sends { cursor, limit }',
                provide: async (args) => appLogs.page(String(args?.cursor ?? '0'), Number(args?.limit ?? 20))
            },
            'tenant.risk': {
                provide: async (_args, ctx) => riskDb.lookup(ctx.senderId)
            }
        }
    },
    response: { include: ['reason', 'analysis', 'report'] }
}
```

Agent (serious case only):

```json
{
  "verdict": "NEED",
  "need": ["body"],
  "skills": [
    { "name": "logs.chunk", "args": { "cursor": "0", "limit": 20 } },
    "tenant.risk"
  ]
}
```

Follow-up includes `skillResults: [{ name, ok, data, truncated? }]` and `deniedSkills` for names you did not declare. Unknown skills never run. `provide` throwing becomes `{ ok: false, error }`. Each result is clipped at `maxResultBytes`.

`payload.maxFollowUps` (default **1**, hard cap **4**) is how many NEED hops run after the first POST. `timeoutMs` is the budget for the **sync** hops + `provide`. Keep providers fast.

## Memory between requests

The agent is still per-`inspect()`. To keep a small blob across requests (same sender / your key), enable store-backed memory:

```ts
remoteAgent: {
    memory: {
        enabled: true,
        // key: (ctx) => ctx.senderId || ctx.ip,
        maxBytes: 4096,
        ttlMs: 30 * 60_000
    }
}
```

Guard sends `memory` on the next envelope. The agent updates it with `remember` or `memory` on the response. Stored at `ug:agent:mem:…` (MemoryStore pin / Redis). This is not a chat log and not a SIEM.

## Async investigate (don’t stall the request)

If the verdict is ready but the report/skills should continue off the request path:

```ts
remoteAgent: {
    investigateAsync: {
        enabled: true,
        timeoutMs: 5000, // separate budget for the background hops
        onComplete: ({ requestId, req, decision }) => tickets.update(requestId, decision.agentReport)
    }
}
```

Agent:

```json
{ "verdict": "MONITOR", "riskScore": 40, "investigate": true, "need": ["body"] }
```

`inspect()` returns that verdict immediately (`investigationPending: true`). Background hops use `phase: "investigate"`. When finished: `onComplete` and EventBus `agentInvestigationComplete`. A failure in the background does **not** change the response already sent (fail-open for the report, not the request).

**Is this a good idea?** Yes, if the catalog is small, need-to-know, and chunked. No, if every request dumps “full logs” or the agent can invent skill names. Do not declare a skill that returns secrets, session cookies, or raw `Authorization`.

**Declared return:** `response.include` gates `reason`, `threats`, `analysis`, `report`. Verdict / `riskScore` / `action` are always read (enforcement). Extra JSON keys are ignored. Report still never goes on the audit line.

---

## What your agent must return

Minimum (enforcement only):

```json
{
  "verdict": "ALLOW",
  "riskScore": 12,
  "reason": "optional human text",
  "action": "ALLOW",
  "threats": []
}
```

Plus (analysis / reports — the agent layer):

```json
{
  "verdict": "BLOCK",
  "riskScore": 91,
  "reason": "jailbreak",
  "analysis": "Instruction-override phrasing in the chat body; local inspectors were clean.",
  "report": {
    "title": "Prompt injection",
    "summary": "Ignore-previous pattern on POST /api/chat",
    "severity": "HIGH",
    "findings": ["IGNORE_PREVIOUS_INSTRUCTIONS"],
    "markdown": "## Finding\nThe user asked the model to drop its system prompt.",
    "extra": { "ticketHint": "SEC-12" }
  }
}
```

| Field | Rules |
|---|---|
| `verdict` | `ALLOW` \| `BLOCK` \| `MONITOR` \| `QUARANTINE` \| `CRITICAL_THREAT` (alias of BLOCK) |
| `allowed` | If present (boolean), it wins over `verdict` |
| `riskScore` | 0–100. If omitted, derived from verdict |
| `reason` | Short machine/human reason. 403 only shows it when `exposeDecisionDetails: true` |
| `action` | Optional override |
| `threats` | Optional array; Guard creates `REMOTE_AGENT_VERDICT` if you block without it |
| `analysis` or `agentAnalysis` | Optional string (or `{ summary }`). Copied to `decision.agentAnalysis` |
| `report` or `agentReport` | Optional object. Copied to `decision.agentReport` (`title`, `summary`, `severity`, `findings`, `markdown`, `extra`) |

Guard **does not** put `analysis` / `report` on the audit line (audit stays `requestId`, score, path, …). Your app decides who sees the report:

```ts
guard.eventBus.on('requestBlocked', ({ decision }) => {
    if (decision.agentReport) notifySoc(decision.agentReport);
});
```

Do not treat `markdown` as trusted HTML. The agent is in your trust boundary; still sanitize before rendering.

HTTP status outside 2xx, timeout, or invalid JSON → **failure**. `failOpen: true` (default) uses the local decision. `failClosed: true` **blocks**. See [ENTERPRISE.md](ENTERPRISE.md).

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
