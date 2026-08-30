/**
 * Custom analysis webhook (schema 1.0).
 * Rules always run. Optional OpenAI-compatible LLM when AGENT_LLM_URL + AGENT_LLM_TOKEN are set.
 *
 *   npx tsx examples/custom-agent-server.ts
 */
import http from 'http';

const port = Number(process.env.PORT || 8787);

const RULES: { pattern: RegExp; reason: string; score: number }[] = [
    { pattern: /ignore\s+(all\s+)?(previous|prior)\s+instructions/i, reason: 'jailbreak: ignore previous instructions', score: 88 },
    { pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)/i, reason: 'jailbreak: disregard rules', score: 88 },
    { pattern: /override\s+(the\s+)?system\s+prompt/i, reason: 'jailbreak: system prompt override', score: 88 },
    { pattern: /act\s+as\s+(an?\s+)?(unfiltered|jailbroken|dan|evil|unrestricted)\b/i, reason: 'jailbreak: act-as persona', score: 85 },
    { pattern: /;\s*(DROP|DELETE|ALTER|TRUNCATE)\s+TABLE\b/i, reason: 'sqli: destructive', score: 90 },
    { pattern: /UNION\s+SELECT\s[\s\S]{0,200}\sFROM\b/i, reason: 'sqli: union select', score: 90 },
    { pattern: /\bOR[\s+]+1[\s+]*=[\s+]*1\b/i, reason: 'sqli: tautology', score: 85 },
    { pattern: /\bSLEEP\s*\(\s*\d{1,4}\s*\)/i, reason: 'sqli: sleep', score: 85 }
];

export interface AgentVerdict {
    verdict: 'ALLOW' | 'BLOCK';
    riskScore: number;
    reason: string;
}

export function scoreWithRules(text: string): AgentVerdict {
    for (const rule of RULES) {
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(text)) {
            return { verdict: 'BLOCK', riskScore: rule.score, reason: rule.reason };
        }
    }
    return { verdict: 'ALLOW', riskScore: 4, reason: 'ok' };
}

function extractText(payload: any): string {
    const local = payload.localAnalysis?.threats as Array<{ summary?: string }> | undefined;
    const localHint = local?.map(t => t.summary).join(' ') || '';
    return [
        JSON.stringify(payload.request?.body ?? payload.content ?? ''),
        String(payload.request?.path || ''),
        JSON.stringify(payload.request?.query || {}),
        localHint
    ].join('\n');
}

function completionsUrl(raw: string): string {
    if (raw.includes('/chat/completions')) return raw;
    return `${raw.replace(/\/$/, '')}/v1/chat/completions`;
}

async function scoreWithLlm(text: string): Promise<AgentVerdict | null> {
    const base = process.env.AGENT_LLM_URL;
    const token = process.env.AGENT_LLM_TOKEN;
    if (!base || !token) return null;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    try {
        const res = await fetch(completionsUrl(base), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`
            },
            body: JSON.stringify({
                model: process.env.AGENT_LLM_MODEL || 'gpt-4o-mini',
                temperature: 0,
                messages: [
                    {
                        role: 'system',
                        content: 'You are a security classifier. Reply with JSON only: {"verdict":"ALLOW"|"BLOCK","riskScore":0-100,"reason":"short"}.'
                    },
                    { role: 'user', content: text.slice(0, 8000) }
                ]
            }),
            signal: controller.signal
        });
        if (!res.ok) return null;
        const data = await res.json() as any;
        const content = String(data.choices?.[0]?.message?.content || '');
        const jsonMatch = content.match(/\{[\s\S]{0,500}\}/);
        if (!jsonMatch) return null;
        const parsed = JSON.parse(jsonMatch[0]);
        const verdict = String(parsed.verdict || '').toUpperCase() === 'BLOCK' ? 'BLOCK' : 'ALLOW';
        const riskScore = Number(parsed.riskScore);
        return {
            verdict,
            riskScore: Number.isFinite(riskScore) ? riskScore : (verdict === 'BLOCK' ? 80 : 4),
            reason: String(parsed.reason || 'llm')
        };
    } catch {
        return null;
    } finally {
        clearTimeout(timeout);
    }
}

async function analyze(payload: any): Promise<AgentVerdict> {
    const text = extractText(payload);
    const llm = await scoreWithLlm(text);
    if (llm) return llm;
    return scoreWithRules(text);
}

http.createServer((req, res) => {
    if (req.method !== 'POST' || (req.url || '').split('?')[0] !== '/analyze') {
        res.writeHead(404);
        res.end();
        return;
    }

    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on('end', async () => {
        let payload: any = {};
        try {
            payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ verdict: 'ALLOW', riskScore: 0, reason: 'invalid json' }));
            return;
        }

        const decision = await analyze(payload);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(decision));
    });
}).listen(port, () => {
    const llm = process.env.AGENT_LLM_URL ? 'rules + LLM' : 'rules only';
    console.log(`Custom Urano Guard agent on http://127.0.0.1:${port}/analyze (${llm})`);
});
