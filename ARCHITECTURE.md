# 🏛️ Architecture & Developer Blueprint — `@uranotools/urano-guard`

> This document provides a comprehensive technical breakdown of **Urano Guard's** internal architecture, lifecycle pipeline, design principles, extension points, and development roadmap.

---

## 📐 High-Level Architectural Pipeline

Urano Guard operates as a **low-latency security perimeter and AI Web Application Firewall (WAF)** that intercepts requests before reaching application logic or intelligent agent runtimes.

```mermaid
flowchart TD
    classDef ingress fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#fff;
    classDef memory fill:#0f172a,stroke:#22c55e,stroke-width:2px,color:#fff;
    classDef heuristic fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#fff;
    classDef remote fill:#311042,stroke:#c084fc,stroke-width:2px,color:#fff;
    classDef defense fill:#450a0a,stroke:#f87171,stroke-width:2px,color:#fff;
    classDef allow fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#fff;

    REQ([🌐 Incoming HTTP Request]):::ingress --> ADAPTERS[🔌 Ingress Adapter Layer<br/>Express / Fastify / Edge / Http]:::ingress
    
    ADAPTERS --> EVALUATOR{⚡ Evaluator Pipeline}

    subgraph MemoryStage ["1. Zero-Latency Memory Stage (<1ms)"]
        EVALUATOR --> WL{⚪ Whitelisted?}:::memory
        WL -- Yes --> PASS_ALLOW[✅ PASS / ALLOW]:::allow
        WL -- No --> BL{🔴 Blacklisted?}:::memory
        BL -- Yes --> BLOCK_RESP[❌ BLOCK 403]:::defense
        BL -- No --> REPLAY{🔁 Replay / Nonce Valid?}:::memory
        REPLAY -- Invalid --> BLOCK_RESP
        REPLAY -- Valid --> CACHE{⚡ LRU Cache Hit?}:::memory
        CACHE -- Hit --> PASS_ALLOW
    end

    subgraph HeuristicStage ["2. Local Heuristic Engine (~2ms)"]
        CACHE -- Miss --> INSPECTORS[🔍 Heuristic Inspectors Array]:::heuristic
        INSPECTORS --> PROMPT[🧠 Prompt Injection]:::heuristic
        INSPECTORS --> PADDING[🛡️ Padding Evasion >8KB]:::heuristic
        INSPECTORS --> SQLI[💉 SQL / OS Command Injection]:::heuristic
        INSPECTORS --> BOT[🤖 Bot Fuzzing / Scanners]:::heuristic
        INSPECTORS --> URL[🔗 Malicious URLs / SSRF]:::heuristic
    end

    INSPECTORS --> THREAT_CHECK{Threat Detected?}
    
    THREAT_CHECK -- Yes (Score ≥ 60) --> DEFENSE_MODE{Active Defense Mode}:::defense
    DEFENSE_MODE --> TARPIT[⏳ Tarpit Delay Generator]:::defense
    DEFENSE_MODE --> HONEY[🍯 Decoy Honey-Tokens]:::defense
    DEFENSE_MODE --> BLOCK_RESP

    THREAT_CHECK -- No Threats --> REMOTE_AI{Deep AI Agent Enabled?}

    subgraph RemoteStage ["3. Remote AI Analysis (with Circuit Breaker)"]
        REMOTE_AI -- Yes --> CB{⚡ Circuit Breaker<br/>CLOSED / HALF_OPEN?}:::remote
        CB -- Closed --> AGENT_QUERY[🤖 Remote Urano Cyber Agent Webhook]:::remote
        CB -- Open / Tripped --> LOCAL_FALLBACK[⚡ Local Heuristic Fallback]:::memory
        AGENT_QUERY -- Clean --> SANITIZE
        AGENT_QUERY -- Critical --> BLOCK_RESP
    end

    REMOTE_AI -- No --> SANITIZE[🔒 PII Masker & Data Sanitizer]:::allow
    LOCAL_FALLBACK --> SANITIZE
    
    SANITIZE --> PASS_ALLOW --> APP([🚀 Target Application Handler]):::allow
    
    BLOCK_RESP -.-> EVENTBUS([📡 Telemetry EventBus]):::ingress
    PASS_ALLOW -.-> EVENTBUS
```

---

## ⚡ Tri-State Circuit Breaker State Machine

When communicating with upstream AI evaluators, the Circuit Breaker guarantees zero service degradation via auto-recovery state transitions:

```mermaid
stateDiagram-v2
    [*] --> CLOSED : Initial Healthy State
    
    CLOSED --> OPEN : Consecutive Failures >= threshold OR Latency > timeout
    note right of OPEN : Bypasses Remote AI\nZero-latency local fallback
    
    OPEN --> HALF_OPEN : After recoveryTimeMs (30s)
    note right of HALF_OPEN : Probes with single test request
    
    HALF_OPEN --> CLOSED : Probe Successful (Latency OK)
    HALF_OPEN --> OPEN : Probe Failed (Trip again)
```

---

## 🔄 End-to-End Request Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Client as 🌐 Client / Attacker
    participant Adapter as 🔌 Framework Adapter
    participant Evaluator as ⚡ Evaluator Core
    participant Cache as 💾 LRU Cache
    participant Inspectors as 🔍 Heuristic Engine
    participant Agent as 🤖 Urano AI Agent
    participant App as 🚀 App Route Handler

    Client->>Adapter: HTTP Request (POST /api/chat)
    Adapter->>Evaluator: inspect(GuardRequestContext)
    
    Evaluator->>Cache: checkCache(hash)
    alt Cache Hit
        Cache-->>Evaluator: Cached ALLOW Decision (<1ms)
    else Cache Miss
        Evaluator->>Inspectors: runAllInspectors(body, headers)
        Inspectors-->>Evaluator: ThreatIncident[] (Heuristics Clean)
        
        opt Deep AI Enabled & Circuit Closed
            Evaluator->>Agent: POST /webhook (AI Verification)
            Agent-->>Evaluator: Verdict: ALLOW (Risk: 0)
        end
    end

    Evaluator-->>Adapter: SecurityDecision { allowed: true, sanitizedBody }
    Adapter->>App: Forward sanitized request
    App-->>Client: 200 OK Response
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

| Component | Status | Priority | Target Release |
|---|:---:|:---:|:---:|
| **Tri-State Circuit Breaker & Fail-Open** | ✅ Complete | High | v1.0.0 |
| **Deep Padding Evasion Inspector (>8KB)** | ✅ Complete | High | v1.0.0 |
| **Anti-Replay Nonce + Timestamp Guard** | ✅ Complete | High | v1.0.0 |
| **Semantic Campaign Rate Limiter** | ✅ Complete | High | v1.0.0 |
| **Behavioral Request Fingerprinter** | ✅ Complete | High | v1.0.0 |
| **Decoy Honeypot & Tarpit Engine** | ✅ Complete | High | v1.0.0 |
| **GraphQL Introspection & Depth Inspector** | ✅ Complete | Medium | v1.0.0 |
| **JWT Tampering & Algorithm Confusion Inspector** | ✅ Complete | High | v1.0.0 |
| **Hono Adapter** | ✅ Complete | Medium | v1.0.0 |
| **Configurable BYO Remote Agent** | ✅ Complete | High | v1.0.0 |
| **OpenTelemetry / Prometheus Metrics Exporter** | 🚧 Interface + EventBus counters | High | v1.2.0 |
| **Elysia.js Adapter** | 🚧 Planned | Medium | v1.1.0 |
| **WebAssembly (WASM) Custom Rules Engine** | 💡 Proposed | Low | v2.0.0 |
