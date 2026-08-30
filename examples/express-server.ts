import express from 'express';
import { createUranoGuard } from '../src';

const app = express();
app.use(express.json({
    verify: (req: any, _res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

const guard = createUranoGuard({
    securityMode: 'block_threats',
    trustProxy: false,
    exposeDecisionDetails: false,
    enableCache: true,
    cacheTtlMs: 60_000,
    routePolicies: [
        { path: '/health', method: 'GET', skip: true }
    ],
    // Optional: your webhook instead of Urano Cloud. See CUSTOM_AGENT.md
    remoteAgent: process.env.AGENT_URL
        ? {
            url: process.env.AGENT_URL,
            timeoutMs: 1500,
            failOpen: true,
            invokeWhen: 'local_clean',
            auth: process.env.AGENT_TOKEN
                ? { type: 'bearer', token: process.env.AGENT_TOKEN }
                : undefined,
            payload: {
                include: ['method', 'path', 'body', 'localThreats', 'securityMode'],
                extra: { app: 'demo' }
            }
        }
        : undefined,
    onThreatDetected: (threat) => {
        console.warn(`[ALERT] ${threat.category}: ${threat.summary}`);
    }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/api/webhook/incoming', guard.express(), (req, res) => {
    res.json({ success: true, payload: req.body });
});

app.listen(3000, () => {
    console.log('Protected server on http://localhost:3000');
});
