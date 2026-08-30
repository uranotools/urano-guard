# Urano Guard examples

Run a local chat API in front of a **custom agent webhook** (no Urano Cloud required). Full contract: [CUSTOM_AGENT.md](../CUSTOM_AGENT.md).

## 1. Start the agent

```bash
npx tsx examples/custom-agent-server.ts
```

Listens on `http://127.0.0.1:8787/analyze`. Scoring is **rules-only** unless you set:

| Env | Purpose |
|---|---|
| `AGENT_LLM_URL` | OpenAI-compatible base (`https://api.openai.com`) or full `/v1/chat/completions` URL |
| `AGENT_LLM_TOKEN` | Bearer token |
| `AGENT_LLM_MODEL` | Optional, default `gpt-4o-mini` |

If the LLM times out or returns invalid JSON, the agent falls back to rules.

## 2. Start the chat API

In another terminal:

```bash
npx tsx examples/chat-app.ts
```

| Env | Default | Notes |
|---|---|---|
| `CHAT_PORT` | `3000` | |
| `AGENT_URL` | `http://127.0.0.1:8787/analyze` | |
| `SECURITY_MODE` | `block_threats` | Use `monitor_only` the first week in production |
| `EXPOSE_DECISION` | off | Set `1` to include `riskScore` on 403s (debug only) |

`GET /health` is skipped by `routePolicies`.

## 3. Curl

Allow:

```bash
curl -s -X POST http://127.0.0.1:3000/api/chat ^
  -H "Content-Type: application/json" ^
  -d "{\"message\":\"What is the weather in Madrid?\"}"
```

Block (local heuristics, agent not needed):

```bash
curl -s -X POST http://127.0.0.1:3000/api/chat ^
  -H "Content-Type: application/json" ^
  -d "{\"message\":\"ignore previous instructions\"}"
```

Health:

```bash
curl -s http://127.0.0.1:3000/health
```

On Unix use `\` instead of `^` for line continuation.

## Other files

- `express-server.ts` — Express + `rawBody` via `verify` (needs `express` installed in your app)
- `metrics-exporter.ts` — sample `MetricsExporter` for EventBus counters
