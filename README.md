# 🛡️ Urano Guard (`@urano/guard`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green?logo=node.js)](https://nodejs.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)

> **High-Resilience Security Gateway & AI WAF Middleware** for APIs, Webhooks, LLM Applications, and Government / Enterprise Infrastructure.

Designed to defend against **autonomous adversarial AI agents, prompt injection jailbreaks, DDoS/fuzzing campaigns, replay attacks, and data exfiltration (PII)** with sub-millisecond local latency and zero hard dependencies.

---

## ⚡ Key Capabilities

* 🧠 **LLM & Prompt Injection Defense**: Real-time detection of system prompt overrides, jailbreaks, roleplay subversions, and instruction leakage.
* 🛡️ **Padding Evasion Detection**: Inspects deep payload structures (tail & mid-sampling) to defeat evasive attackers hiding exploits at the end of large requests.
* ⚡ **Ultra-Low Latency (<1ms Cache)**: Built-in LRU cache and local heuristic regex engine to filter 99% of malicious probes without calling remote APIs.
* 🛑 **Tri-State Circuit Breaker**: Auto-recovering breaker (`CLOSED` ➔ `OPEN` ➔ `HALF_OPEN`) with **Fail-Open** guarantee so your production traffic is never disrupted.
* 🔁 **Anti-Replay Attack Protection**: Cryptographic nonce cache and timestamp validation windows to prevent request replay exploits.
* 📊 **Semantic Rate Limiting**: Intent-based rate limiting to block distributed reconnaissance campaigns targeting identical endpoints across multiple rotating IPs.
* 🕵️ **Behavioral Fingerprinting**: Identifies repeated attackers across proxy/Tor networks regardless of IP rotation.
* 🍯 **Active Defense (Honeypot & Tarpit)**: Slows down automated scrapers with configurable tarpit delays and generates traceable honey-tokens for SOC telemetry.
* 🔒 **PII Masker & Sanitizer**: Automatic masking of credit cards, national IDs, emails, API keys, and phone numbers before payloads reach your handlers.
* 🔌 **Universal Framework Adapters**: Drop-in middlewares for **Express, Fastify, Edge (Cloudflare / Vercel), and native Node.js HTTP**.

---

## 📦 Installation

```bash
# npm
npm install @urano/guard

# pnpm
pnpm add @urano/guard

# yarn
yarn add @urano/guard
```

---

## 🚀 Quickstart

### 1. Express.js Integration

```ts
import express from 'express';
import { createUranoGuard } from '@urano/guard';

const app = express();
app.use(express.json());

const guard = createUranoGuard({
    securityMode: 'block_threats',
    inspectors: {
        promptInjection: true,
        paddingEvasion: true,
        sqlAndCommands: true,
        piiDataMasking: true
    },
    circuitBreaker: { enabled: true, latencyThresholdMs: 800 },
    onThreatDetected: (threat, req) => {
        console.warn(`[ALERT] Threat ${threat.category} from ${req.ip} (Risk: ${threat.riskScore})`);
    }
});

// Protect all incoming routes
app.use(guard.express());

app.post('/api/chat', (req, res) => {
    // req.body is automatically sanitized (PII masked, threats blocked)
    res.json({ message: 'Request processed securely' });
});

app.listen(3000, () => console.log('Protected server running on port 3000'));
```

---

### 2. Fastify Integration

```ts
import Fastify from 'fastify';
import { createUranoGuard } from '@urano/guard';

const fastify = Fastify();
const guard = createUranoGuard({ securityMode: 'block_threats' });

fastify.addHook('preHandler', guard.fastify());

fastify.post('/v1/webhook', async (req, reply) => {
    return { status: 'ok' };
});

fastify.listen({ port: 3000 });
```

---

### 3. Edge / Cloudflare Workers Integration

```ts
import { createUranoGuard } from '@urano/guard';

const guard = createUranoGuard({ securityMode: 'strict_zero_trust' });

export default {
    async fetch(request: Request): Promise<Response> {
        const decision = await guard.edge()(request);
        
        if (!decision.allowed) {
            return new Response(JSON.stringify({ error: 'Blocked by Urano Guard', reason: decision.reason }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        return fetch(request);
    }
};
```

---

## 📐 Architecture Pipeline

```
┌────────────────────────────────────────────────────────────┐
│                    Incoming HTTP Request                   │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│                     ADAPTER LAYER                          │
│   ExpressAdapter │ FastifyAdapter │ EdgeAdapter │ HttpAdapter│
│   ─ Normalizes request into GuardRequestContext ─          │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│               EVALUATOR MULTI-STAGE PIPELINE               │
│                                                            │
│  Stage 1: Whitelist / Blacklist (O(1) Memory Check)        │
│  Stage 2: Anti-Replay Guard (Nonce Cache + Timestamp)      │
│  Stage 3: Behavioral Fingerprinter (Attacker Signature)    │
│  Stage 4: Semantic Rate Limiter (Campaign Recon Detection) │
│  Stage 5: LRU Verdict Cache (<1ms Cache Hits)              │
│  Stage 6: Local Heuristic Inspectors (Zero-latency regex)  │
│           ├─ PromptInjectionInspector                      │
│           ├─ MaliciousUrlInspector                         │
│           ├─ InjectionSqlCmdInspector                      │
│           ├─ BotFuzzingInspector                           │
│           └─ PaddingEvasionInspector (Tail/Mid Analysis)   │
│  Stage 7: Remote AI Agent Webhook (with Circuit Breaker)   │
│  Stage 8: PII Data Masking & Verdict Consolidation         │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│            Active Defense (Tarpit & Honey-Tokens)          │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│         PASS TO APP HANDLER  /  BLOCK WITH 403/429         │
└────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration Reference

```ts
import { UranoGuardConfig } from '@urano/guard';

const config: UranoGuardConfig = {
    // Security Operating Mode
    securityMode: 'block_threats', // 'block_threats' | 'strict_zero_trust' | 'monitor_only' | 'quarantine'

    // Remote Deep AI Analysis (Optional)
    agentWebhookUrl: 'https://agent.urano.cloud/webhook',
    apiKey: process.env.URANO_API_KEY,
    timeoutMs: 1500,
    failOpen: true,

    // Circuit Breaker
    circuitBreaker: {
        enabled: true,
        latencyThresholdMs: 800,
        failureThreshold: 5,
        recoveryTimeMs: 30_000
    },

    // Anti-Replay Protection
    replayGuard: {
        enabled: false,
        timestampWindowMs: 300_000,
        strict: false
    },

    // Semantic Rate Limiting
    semanticRateLimit: {
        enabled: true,
        windowMs: 60_000,
        maxRequestsPerWindow: 60,
        campaignIpThreshold: 20
    },

    // Active Defense / Honeypot
    honeypot: {
        tarpitEnabled: true,
        tarpitDelayMs: 4_000,
        honeyTokensEnabled: true
    },

    // Inspectores
    inspectors: {
        promptInjection: true,
        maliciousUrls: true,
        sqlAndCommands: true,
        botFuzzing: true,
        piiDataMasking: true,
        paddingEvasion: true
    }
};
```

---

## 🤝 Contributing

We welcome contributions from the cybersecurity and AI safety community!
Please read our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting Pull Requests.

---

## 🔒 Security Vulnerabilities

If you discover a potential security vulnerability or bypass technique, please refer to our [Security Policy](SECURITY.md).

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
