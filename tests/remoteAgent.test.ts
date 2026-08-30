import { afterEach, describe, expect, it, vi } from 'vitest';
import { RemoteAgentClient, resolveRemoteAgentConfig, shouldInvokeRemoteWithRange } from '../src/core/RemoteAgentClient';
import { MemoryStore } from '../src/core/SharedStore';
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

    it('passes through agent analysis and report', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: true,
            headers: { get: () => null },
            text: async () => JSON.stringify({
                verdict: 'BLOCK',
                riskScore: 91,
                reason: 'jailbreak',
                analysis: 'Model saw an instruction-override attempt.',
                report: {
                    title: 'Prompt injection',
                    summary: 'Ignore-previous pattern in /api/chat',
                    severity: 'HIGH',
                    findings: ['IGNORE_PREVIOUS_INSTRUCTIONS'],
                    markdown: '## Finding\nInstruction override.',
                    extra: { ticketHint: 'SEC-12' }
                }
            })
        })));
        const client = new RemoteAgentClient({ config: { url: 'https://x' } });
        const decision = await client.query(ctx(), { threats: [], maxRiskScore: 0 });
        expect(decision?.allowed).toBe(false);
        expect(decision?.agentAnalysis).toContain('instruction-override');
        expect(decision?.agentReport?.title).toBe('Prompt injection');
        expect(decision?.agentReport?.extra).toEqual({ ticketHint: 'SEC-12' });
    });

    it('follows up once when the agent NEEDs a declared field', async () => {
        const hops: any[] = [];
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
            const body = JSON.parse(init.body);
            hops.push(body);
            if (!body.followUp) {
                return {
                    ok: true,
                    headers: { get: () => null },
                    text: async () => JSON.stringify({ verdict: 'NEED', need: ['body', 'rawBody'] })
                };
            }
            return {
                ok: true,
                headers: { get: () => null },
                text: async () => JSON.stringify({
                    verdict: 'BLOCK',
                    riskScore: 90,
                    analysis: 'Used the body',
                    report: { title: 'Should be stripped' }
                })
            };
        }));

        const client = new RemoteAgentClient({
            config: {
                url: 'https://agent.example/analyze',
                payload: {
                    include: ['method', 'path'],
                    onRequest: ['body']
                },
                response: { include: ['analysis'] }
            },
            useLegacyPayload: false
        });

        const decision = await client.query(ctx({ path: '/chat', body: { message: 'secret-payload' } }), {
            threats: [],
            maxRiskScore: 0
        });

        expect(hops).toHaveLength(2);
        expect(hops[0].request.body).toBeUndefined();
        expect(hops[0].capabilities.canDisclose).toContain('body');
        expect(hops[1].followUp).toBe(true);
        expect(hops[1].request.body).toEqual({ message: 'secret-payload' });
        expect(hops[1].denied).toEqual(['rawBody']);
        expect(hops[0].requestId).toBe(hops[1].requestId);
        expect(decision?.allowed).toBe(false);
        expect(decision?.agentAnalysis).toBe('Used the body');
        expect(decision?.agentReport).toBeUndefined();
        expect(decision?.reason).toBeUndefined();
    });

    it('does not disclose undeclared fields and fail-opens a NEED with no grant', async () => {
        let calls = 0;
        vi.stubGlobal('fetch', vi.fn(async () => {
            calls += 1;
            return {
                ok: true,
                headers: { get: () => null },
                text: async () => JSON.stringify({ verdict: 'NEED', need: ['body'] })
            };
        }));
        const client = new RemoteAgentClient({
            config: {
                url: 'https://x',
                payload: { include: ['path'], onRequest: ['headers'] }
            },
            useLegacyPayload: false
        });
        const decision = await client.query(ctx({ body: 'hidden' }), { threats: [], maxRiskScore: 0 });
        expect(calls).toBe(1);
        expect(decision).toBeNull();
    });

    it('refuses a second NEED hop', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: true,
            headers: { get: () => null },
            text: async () => JSON.stringify({ verdict: 'NEED', need: ['body'] })
        })));
        const client = new RemoteAgentClient({
            config: {
                url: 'https://x',
                payload: { include: ['path'], onRequest: ['body'] }
            },
            useLegacyPayload: false
        });
        const decision = await client.query(ctx({ body: 'x' }), { threats: [], maxRiskScore: 0 });
        expect(decision).toBeNull();
    });

    it('runs a declared skill on NEED and chunks args through provide', async () => {
        const hops: any[] = [];
        const seenArgs: unknown[] = [];
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
            const body = JSON.parse(init.body);
            hops.push(body);
            if (!body.followUp) {
                return {
                    ok: true,
                    headers: { get: () => null },
                    text: async () => JSON.stringify({
                        verdict: 'NEED',
                        skills: [
                            { name: 'logs.chunk', args: { cursor: '0', limit: 2 } },
                            'logs.full',
                            { name: 'not-declared' }
                        ]
                    })
                };
            }
            return {
                ok: true,
                headers: { get: () => null },
                text: async () => JSON.stringify({ verdict: 'ALLOW', riskScore: 8, analysis: 'enough context' })
            };
        }));

        const client = new RemoteAgentClient({
            config: {
                url: 'https://agent.example/analyze',
                payload: { include: ['path'] },
                skills: {
                    catalog: {
                        'logs.chunk': {
                            description: 'Window of app logs',
                            provide: (args) => {
                                seenArgs.push(args);
                                return { lines: ['a', 'b'], nextCursor: '2' };
                            }
                        },
                        'logs.full': {
                            provide: () => 'LINE\n'.repeat(5000)
                        }
                    },
                    maxResultBytes: 32
                },
                response: { include: ['analysis'] }
            },
            useLegacyPayload: false
        });

        const decision = await client.query(ctx({ path: '/chat' }), { threats: [], maxRiskScore: 0 });
        expect(hops).toHaveLength(2);
        expect(hops[0].capabilities.canInvoke).toEqual(['logs.chunk', 'logs.full']);
        expect(hops[1].deniedSkills).toEqual(['not-declared']);
        expect(hops[1].skillResults[0]).toMatchObject({
            name: 'logs.chunk',
            ok: true,
            data: { lines: ['a', 'b'], nextCursor: '2' }
        });
        expect(hops[1].skillResults[1].name).toBe('logs.full');
        expect(hops[1].skillResults[1].truncated).toBe(true);
        expect(seenArgs[0]).toEqual({ cursor: '0', limit: 2 });
        expect(decision?.allowed).toBe(true);
        expect(decision?.agentAnalysis).toBe('enough context');
    });

    it('allows up to maxFollowUps NEED hops', async () => {
        const hops: any[] = [];
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
            const body = JSON.parse(init.body);
            hops.push(body);
            if (hops.length === 1) {
                return {
                    ok: true,
                    headers: { get: () => null },
                    text: async () => JSON.stringify({ verdict: 'NEED', need: ['body'] })
                };
            }
            if (hops.length === 2) {
                return {
                    ok: true,
                    headers: { get: () => null },
                    text: async () => JSON.stringify({ verdict: 'NEED', need: ['headers'] })
                };
            }
            return {
                ok: true,
                headers: { get: () => null },
                text: async () => JSON.stringify({ verdict: 'ALLOW', riskScore: 3 })
            };
        }));
        const client = new RemoteAgentClient({
            config: {
                url: 'https://x',
                payload: {
                    include: ['path'],
                    onRequest: ['body', 'headers'],
                    maxFollowUps: 2
                }
            },
            useLegacyPayload: false
        });
        const decision = await client.query(ctx({ path: '/a', body: { m: 1 }, headers: { 'user-agent': 't' } }), {
            threats: [],
            maxRiskScore: 0
        });
        expect(hops).toHaveLength(3);
        expect(hops[2].followUp).toBe(true);
        expect(hops[2].request.body).toEqual({ m: 1 });
        expect(hops[2].request.headers['user-agent']).toBe('t');
        expect(decision?.allowed).toBe(true);
    });

    it('stores remember blobs and sends them on the next request', async () => {
        const hops: any[] = [];
        let n = 0;
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
            hops.push(JSON.parse(init.body));
            n += 1;
            if (n === 1) {
                return {
                    ok: true,
                    headers: { get: () => null },
                    text: async () => JSON.stringify({
                        verdict: 'ALLOW',
                        riskScore: 1,
                        remember: { lastPath: '/one', hits: 1 }
                    })
                };
            }
            return {
                ok: true,
                headers: { get: () => null },
                text: async () => JSON.stringify({ verdict: 'ALLOW', riskScore: 1 })
            };
        }));
        const store = new MemoryStore();
        const client = new RemoteAgentClient({
            config: {
                url: 'https://x',
                payload: { include: ['path'] },
                memory: { enabled: true, ttlMs: 60_000 }
            },
            store,
            useLegacyPayload: false
        });
        const a = ctx({ path: '/one', senderId: 'u1', ip: 'u1' });
        await client.query(a, { threats: [], maxRiskScore: 0 });
        await client.query(ctx({ path: '/two', senderId: 'u1', ip: 'u1' }), { threats: [], maxRiskScore: 0 });
        expect(hops[1].memory).toEqual({ lastPath: '/one', hits: 1 });
        expect(await store.get('ug:agent:mem:u1')).toEqual({ lastPath: '/one', hits: 1 });
    });

    it('returns immediately when investigate is true and finishes in the background', async () => {
        let hop = 0;
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
            hop += 1;
            const body = JSON.parse(init.body);
            if (hop === 1) {
                expect(body.phase).toBe('sync');
                return {
                    ok: true,
                    headers: { get: () => null },
                    text: async () => JSON.stringify({
                        verdict: 'MONITOR',
                        riskScore: 40,
                        investigate: true,
                        need: ['body']
                    })
                };
            }
            expect(body.phase).toBe('investigate');
            expect(body.request.body).toEqual({ message: 'slow' });
            return {
                ok: true,
                headers: { get: () => null },
                text: async () => JSON.stringify({
                    verdict: 'BLOCK',
                    riskScore: 92,
                    analysis: 'late report'
                })
            };
        }));
        let resolveDone!: (v: any) => void;
        const finished = new Promise<any>(r => { resolveDone = r; });
        const client = new RemoteAgentClient({
            config: {
                url: 'https://x',
                payload: { include: ['path'], onRequest: ['body'] },
                investigateAsync: {
                    enabled: true,
                    timeoutMs: 2000,
                    onComplete: (event) => resolveDone(event)
                },
                response: { include: ['analysis'] }
            },
            useLegacyPayload: false
        });
        const decision = await client.query(ctx({ path: '/chat', body: { message: 'slow' } }), {
            threats: [],
            maxRiskScore: 0
        });
        expect(decision?.allowed).toBe(true);
        expect(decision?.action).toBe('MONITOR');
        expect(decision?.investigationPending).toBe(true);
        expect(decision?.agentAnalysis).toBeUndefined();
        const event = await finished;
        expect(event.decision.allowed).toBe(false);
        expect(event.decision.agentAnalysis).toBe('late report');
    });
});
