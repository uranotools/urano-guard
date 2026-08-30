# Changelog

## 1.1.0

### Features

- Configurable **BYO remote agent** (`remoteAgent`): payload `include`/`extra`, Bearer/header/HMAC, `invokeWhen`, response mapping. See [CUSTOM_AGENT.md](CUSTOM_AGENT.md).
- Text **normalization** before heuristics (NFKC, zero-width strip, optional leet for prompt rules) and SQL comment stripping (`UN/**/ION`).
- Split inspectors: SQL, command injection, XSS; plus JWT tampering and GraphQL abuse.
- Inspection surface: body + query + path + allowlisted headers.
- Route policies, `trustProxy`, quarantine TTL, Hono adapter, injectable logger, EventBus metrics.
- Attack/benign **corpus tests**. Runnable demo: [examples/README.md](examples/README.md).

### Breaking / behavior changes (from 1.0.x)

- `trustProxy` defaults to `false`. `X-Forwarded-For` / `x-user-id` are ignored unless enabled.
- Block responses hide `riskScore` / `reason` unless `exposeDecisionDetails: true`.
- `sqlAndCommands` still enables SQL + command + XSS; prefer the new flags.
- Circuit breaker HALF_OPEN allows a **single** in-flight probe.
- Cache keys hash the full body (no 100-character prefix).

### Migration

`agentWebhookUrl` + `apiKey` still send the legacy `{ sender, content, path, method }` payload. Set `remoteAgent.payload` or `buildPayload` to use schema 1.0.

## 1.0.0

Initial public SDK: local inspectors, Express/Fastify/Edge/HTTP adapters, optional remote webhook.
