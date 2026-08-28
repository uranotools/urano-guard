# 🏛️ Architecture & Developer Blueprint — `@uranotools/urano-guard`

> This document provides a comprehensive technical breakdown of **Urano Guard's** internal architecture, lifecycle pipeline, design principles, extension points, and development roadmap.

---

## 📐 High-Level Architectural Overview

Urano Guard acts as a **non-blocking, low-latency security perimeter and AI Web Application Firewall (WAF)** that sits directly in front of API endpoints, webhook receivers, and intelligent agent runtimes.

```
                                  INCOMING HTTP REQUEST
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. INGRESS & ADAPTER LAYER (src/adapters/)                                             │
│    Normalizes heterogeneous framework requests into a unified GuardRequestContext.      │
│    • ExpressAdapter │ FastifyAdapter │ EdgeAdapter (Cloudflare/Vercel) │ HttpAdapter       │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. PIPELINE ORCHESTRATOR & EVALUATOR (src/core/Evaluator.ts)                           │
│    Executes security inspection stages in order of computational cost (O(1) -> AI).    │
│                                                                                        │
│  [Stage 1] ⚪ Whitelist / 🔴 Blacklist (O(1) ThreatRegistry Memory Lookup)              │
│       │                                                                                │
│  [Stage 2] 🔁 Anti-Replay Guard (Nonce Cache + Timestamp Tolerance Window)            │
│       │                                                                                │
│  [Stage 3] 🕵️ Behavioral Fingerprinter (Attacker Header / Structural Signature)       │
│       │                                                                                │
│  [Stage 4] 📊 Semantic Rate Limiter (Distributed Campaign Reconnaissance Filter)       │
│       │                                                                                │
│  [Stage 5] ⚡ LRU Verdict Cache (<1ms Instant Decision Hit)                           │
│       │                                                                                │
│  [Stage 6] 🔍 Local Heuristic Engine (Zero-dependency Regex Array)                    │
│       ├── PromptInjectionInspector (Jailbreaks, System Overrides)                      │
│       ├── MaliciousUrlInspector (SSRF, Open Redirects)                                 │
│       ├── InjectionSqlCmdInspector (SQLi, OS Command Injection)                        │
│       ├── BotFuzzingInspector (Path traversals, Automated scanners)                    │
│       └── PaddingEvasionInspector (Deep Tail & Mid-Payload Sampling >8KB)              │
│       │                                                                                │
│  [Stage 7] 🧠 Remote Deep AI Agent (Optional / Webhook via Tri-State Circuit Breaker) │
│       │                                                                                │
│  [Stage 8] 🔒 Sanitization & PII Data Masker (Credit Cards, Keys, National IDs)       │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. ACTIVE DEFENSE & VERDICT RESOLUTION (src/core/HoneypotRouter.ts)                    │
│    • ALLOW: Pass sanitized payload to target application handler.                      │
│    • BLOCK: Terminate with 403 Forbidden / 429 Rate Limited.                           │
│    • TARPIT: Inject artificial latency to exhaust attacker/bot compute resources.     │
│    • HONEY-RESPONSE: Return realistic decoy data embedded with traceable Honey-Tokens.│
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 4. TELEMETRY & EVENT BUS (src/core/EventBus.ts)                                        │
│    Publishes asynchronous events for SOC logging, metrics, and incident auditing.      │
│    • threatDetected │ requestBlocked │ requestAllowed │ honeyTokenAccessed             │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ The 5 Golden Rules of Urano Guard Performance

When contributing code or writing new inspectors, you must adhere to these five architectural constraints:

1. **Zero Heavy External Dependencies:** The core SDK must remain ultra-lightweight. No heavy machine-learning packages or native C++ addons in the runtime hot-path.
2. **Sub-Millisecond Heuristic Budget (<2ms):** All local regular expressions and inspectors must execute in $\le 2\text{ms}$. Regular expressions must be audited against Catastrophic Backtracking (ReDoS).
3. **Fail-Open by Design:** If a remote AI evaluation agent fails, times out, or becomes unresponsive, the `CircuitBreaker` trips to `OPEN` and the system defaults to local heuristics without interrupting legitimate traffic.
4. **Bounded Memory Usage:** All caches (Decision LRU, Nonce Store, Fingerprint Table) use strict maximum entry limits and automated sweep/eviction routines to prevent memory leaks in long-running Node.js processes.
5. **Deterministic Immutability:** Context objects (`GuardRequestContext`) are normalized once at ingress; payload transformations (like PII masking) only produce sanitized copies without mutating raw request headers.

---

## 🧩 Extension Points for Contributors

Urano Guard is designed with strict inversion of control. Contributors can extend the SDK in 4 key areas:

### 1. Adding a New Threat Inspector (`src/inspectors/`)

All inspectors extend `InspectorBase` and implement the `inspect(context)` method:

```ts
import { InspectorBase, GuardRequestContext, ThreatIncident } from '@uranotools/urano-guard';

export class GraphQLAbuseInspector extends InspectorBase {
    readonly name = 'GraphQLAbuseInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident | null {
        if (!this.enabled) return null;

        const bodyStr = typeof context.body === 'string' ? context.body : JSON.stringify(context.body || '');
        
        // Fast heuristic check
        if (bodyStr.includes('__schema') || bodyStr.includes('__type')) {
            return {
                id: `thr_gql_${Date.now()}`,
                category: 'CUSTOM',
                severity: 'MEDIUM',
                riskScore: 65,
                summary: 'GraphQL introspection probe detected.',
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip
            };
        }

        return null;
    }
}
```

---

### 2. Adding a Framework Adapter (`src/adapters/`)

Adapters normalize framework-specific request structures into `GuardRequestContext`:

```ts
import { AdapterBase, GuardRequestContext } from '@uranotools/urano-guard';

export class HonoAdapter extends AdapterBase {
    middleware() {
        return async (c: any, next: () => Promise<void>) => {
            const ctx: GuardRequestContext = {
                ip: c.req.header('x-forwarded-for') || '127.0.0.1',
                method: c.req.method,
                path: c.req.path,
                headers: c.req.header(),
                body: await c.req.json().catch(() => ({})),
                timestamp: new Date().toISOString()
            };

            const decision = await this.guard.inspect(ctx);
            if (!decision.allowed) {
                return c.json({ error: 'Blocked by Urano Guard', reason: decision.reason }, 403);
            }

            await next();
        };
    }
}
```

---

### 3. Subscribing to Security Telemetry (`src/core/EventBus.ts`)

Connect Urano Guard events to your custom SIEM, Datadog, or Slack alerting webhook:

```ts
const guard = createUranoGuard({ ... });

guard.eventBus.on('threatDetected', ({ threat, req }) => {
    datadog.increment('waf.threat_detected', 1, [`category:${threat.category}`]);
});

guard.eventBus.on('honeyTokenAccessed', ({ token, req }) => {
    slack.sendAlert(`🚨 ATTACKER TRAPPED: Attacker returned with Honey-Token ${token} from IP ${req.ip}`);
});
```

---

## 🗺️ Architectural Roadmap

Contributors are encouraged to pick up features from our planned roadmap:

| Component | Status | Priority | Target Release |
|---|:---:|:---:|:---:|
| **Tri-State Circuit Breaker & Fail-Open** | ✅ Complete | High | v1.0.0 |
| **Deep Padding Evasion Inspector (>8KB)** | ✅ Complete | High | v1.0.0 |
| **Anti-Replay Nonce + Timestamp Guard** | ✅ Complete | High | v1.0.0 |
| **Semantic Campaign Rate Limiter** | ✅ Complete | High | v1.0.0 |
| **Behavioral Request Fingerprinter** | ✅ Complete | High | v1.0.0 |
| **Decoy Honeypot & Tarpit Engine** | ✅ Complete | High | v1.0.0 |
| **GraphQL Introspection & Depth Inspector** | 🚧 Planned | Medium | v1.1.0 |
| **JWT Tampering & Algorithm Confusion Inspector** | 🚧 Planned | High | v1.1.0 |
| **Hono & Elysia.js Adapters** | 🚧 Planned | Medium | v1.1.0 |
| **OpenTelemetry / Prometheus Metrics Exporter** | 🚧 Planned | High | v1.2.0 |
| **WebAssembly (WASM) Custom Rules Engine** | 💡 Proposed | Low | v2.0.0 |

---

## 🔒 Security Principles

1. **Defense in Depth:** Local heuristics filter common threats; remote AI models evaluate novel adversarial attacks.
2. **Minimal False Positives:** Default risk thresholds ($60/100$) ensure benign developer traffic is never blocked accidentally.
3. **Auditable Incident Traceability:** Every blocked or quarantined request contains a unique incident ID (`thr_...`) with matched pattern telemetry for SOC review.
