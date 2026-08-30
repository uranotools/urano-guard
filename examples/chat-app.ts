/**
 * Protected chat API. Pair with examples/custom-agent-server.ts
 *
 *   npx tsx examples/custom-agent-server.ts
 *   npx tsx examples/chat-app.ts
 *
 * First week in production: SECURITY_MODE=monitor_only
 */
import http from 'http';
import { createUranoGuard } from '../src';

const port = Number(process.env.CHAT_PORT || 3000);
const agentUrl = process.env.AGENT_URL || 'http://127.0.0.1:8787/analyze';
const securityMode = (process.env.SECURITY_MODE as 'block_threats' | 'monitor_only') || 'block_threats';

const guard = createUranoGuard({
    securityMode,
    trustProxy: false,
    exposeDecisionDetails: process.env.EXPOSE_DECISION === '1',
    failOpen: true,
    enableCache: true,
    routePolicies: [
        { path: '/health', method: 'GET', skip: true }
    ],
    remoteAgent: {
        url: agentUrl,
        timeoutMs: 1500,
        failOpen: true,
        invokeWhen: 'local_clean',
        payload: {
            include: ['method', 'path', 'body', 'localThreats', 'securityMode'],
            extra: { app: 'chat-demo' }
        }
    },
    onThreatDetected: (threat) => {
        console.warn(`[ALERT] ${threat.category}: ${threat.summary}`);
    }
});

const inspect = guard.http();

function pathOf(req: http.IncomingMessage): string {
    return (req.url || '/').split('?')[0];
}

function json(res: http.ServerResponse, status: number, body: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
}

http.createServer(async (req, res) => {
    const path = pathOf(req);

    try {
        const allowed = await inspect(req, res);
        if (!allowed) return;

        if (req.method === 'GET' && path === '/health') {
            json(res, 200, { ok: true });
            return;
        }

        if (req.method === 'POST' && path === '/api/chat') {
            const payload = (req as any).body;
            const message = typeof payload === 'string' ? payload : payload?.message ?? payload;
            json(res, 200, {
                reply: 'Request accepted by Urano Guard.',
                echo: message
            });
            return;
        }

        json(res, 404, { error: 'not_found' });
    } catch (err) {
        console.error(err);
        json(res, 500, { error: 'internal_error' });
    }
}).listen(port, () => {
    console.log(`Chat app on http://127.0.0.1:${port} (mode=${securityMode}, agent=${agentUrl})`);
});
