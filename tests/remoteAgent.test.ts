import { afterEach, describe, expect, it, vi } from 'vitest';
import { RemoteAgentClient, resolveRemoteAgentConfig, shouldInvokeRemoteWithRange } from '../src/core/RemoteAgentClient';
import { signHmac } from '../src/utils/crypto';
import { ctx } from './helpers';

afterEach(() => {
    vi.unstubAllGlobals();
});

describe('shouldInvokeRemoteWithRange', () => {
    it('local_clean only when no threats', () => {
        expect(shouldInvokeRemoteWithRange('local_clean', { threats: [], maxRiskScore: 0 }, 30, 59)).toBe(true);
        expect(shouldInvokeRemoteWithRange('local_clean', { threats: [{} as any], maxRiskScore: 80 }, 30, 59)).toBe(false);
    });

    it('local_suspicious only in score band', () => {
        expect(shouldInvokeRemoteWithRange('local_suspicious', { threats: [], maxRiskScore: 40 }, 30, 59)).toBe(true);
        expect(shouldInvokeRemoteWithRange('local_suspicious', { threats: [], maxRiskScore: 10 }, 30, 59)).toBe(false);
    });
});

describe('RemoteAgentClient', () => {
    it('sends a v1 envelope with selected fields', async () => {
        let captured: any;
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
            captured = JSON.parse(init.body);
            return {
                ok: true,
                headers: { get: () => null },
                text: async () => JSON.stringify({ verdict: 'ALLOW', riskScore: 5 })
            };
        }));

        const client = new RemoteAgentClient({
            config: {
                url: 'https://agent.example/analyze',
                payload: {
                    include: ['path', 'method', 'body', 'extra' as any],
                    extra: { app: 'checkout' },
                    maxBodyBytes: 16
                }
            },
            useLegacyPayload: false
        });

        const decision = await client.query(ctx({ path: '/pay', body: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' }), {
            threats: [],
            maxRiskScore: 0
        });
        expect(decision?.allowed).toBe(true);
        expect(captured.schemaVersion).toBe('1.0');
        expect(captured.request.path).toBe('/pay');
        expect(captured.extra.app).toBe('checkout');
        expect(String(captured.request.body).length).toBeLessThanOrEqual(16);
    });

    it('keeps legacy payload when only agentWebhookUrl is set', async () => {
        let captured: any;
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
            captured = JSON.parse(init.body);
            return {
                ok: true,
                headers: { get: () => null },
                text: async () => JSON.stringify({ verdict: 'ALLOW', riskScore: 0 })
            };
        }));
        const resolved = resolveRemoteAgentConfig({ agentWebhookUrl: 'https://agent.urano.cloud/hook', apiKey: 'k' });
        const client = new RemoteAgentClient({ config: resolved!, useLegacyPayload: true });
        await client.query(ctx({ body: { msg: 'hi' }, path: '/x', method: 'POST' }), { threats: [], maxRiskScore: 0 });
        expect(captured.sender).toBeDefined();
        expect(captured.content).toEqual({ msg: 'hi' });
        expect(captured.schemaVersion).toBeUndefined();
    });

    it('maps custom responses and fail-opens on invalid JSON', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: true,
            headers: { get: () => null },
            text: async () => 'not-json'
        })));
        const client = new RemoteAgentClient({ config: { url: 'https://x' } });
        expect(await client.query(ctx(), { threats: [], maxRiskScore: 0 })).toBeNull();
    });

    it('verifies response HMAC', async () => {
        const body = JSON.stringify({ verdict: 'BLOCK', riskScore: 90, reason: 'bad' });
        const secret = 'resp-secret';
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: true,
            headers: { get: () => signHmac(body, secret) },
            text: async () => body
        })));
        const client = new RemoteAgentClient({
            config: { url: 'https://x', response: { hmacSecret: secret } }
        });
        const decision = await client.query(ctx(), { threats: [], maxRiskScore: 0 });
        expect(decision?.allowed).toBe(false);
        expect(decision?.source).toBe('REMOTE_AGENT');
    });

    it('supports mapResponse', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: true,
            headers: { get: () => null },
            text: async () => JSON.stringify({ evil: true, score: 77 })
        })));
        const client = new RemoteAgentClient({
            config: {
                url: 'https://x',
                mapResponse: (json: any) => ({
                    allowed: !json.evil,
                    riskScore: json.score,
                    reason: 'mapped'
                })
            }
        });
        const decision = await client.query(ctx(), { threats: [], maxRiskScore: 0 });
        expect(decision?.allowed).toBe(false);
        expect(decision?.riskScore).toBe(77);
    });
});
