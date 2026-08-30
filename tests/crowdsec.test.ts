import { describe, expect, it, vi, afterEach } from 'vitest';
import { createUranoGuard } from '../src/core/UranoGuard';
import { createCrowdSecLookup, createCrowdSecSkill } from '../src/core/CrowdSec';
import { CROWDSEC_SKILL_NAME } from '../src/types/crowdsec';
import { resolveRemoteAgentConfig } from '../src/core/RemoteAgentClient';
import { ConfigValidationError } from '../src/core/validateConfig';
import { ctx } from './helpers';

afterEach(() => {
    vi.unstubAllGlobals();
});

describe('CrowdSec optional integration', () => {
    it('does not require a CrowdSec key when crowdsec is unset', () => {
        expect(() => createUranoGuard({})).not.toThrow();
    });

    it('requires apiKey when url is set without lookup', () => {
        expect(() => createUranoGuard({
            crowdsec: { url: 'http://127.0.0.1:8080' }
        })).toThrow(ConfigValidationError);
    });

    it('accepts injected lookup without an API key', async () => {
        const lookup = createCrowdSecLookup({
            lookup: async (ip) => ({
                ip,
                banned: ip === '9.9.9.9',
                decisions: ip === '9.9.9.9' ? [{ type: 'ban', reason: 'community' }] : []
            })
        });
        expect((await lookup('1.1.1.1')).banned).toBe(false);
        expect((await lookup('9.9.9.9')).banned).toBe(true);
    });

    it('queries LAPI with X-Api-Key and fail-opens on errors', async () => {
        vi.stubGlobal('fetch', vi.fn(async (url: string, init: any) => {
            expect(url).toContain('/v1/decisions?ip=8.8.8.8');
            expect(init.headers['X-Api-Key']).toBe('bouncer');
            return { ok: true, json: async () => [{ type: 'ban', reason: 'scan' }] };
        }));
        const lookup = createCrowdSecLookup({
            url: 'http://127.0.0.1:8080',
            apiKey: 'bouncer'
        });
        const hit = await lookup('8.8.8.8');
        expect(hit.banned).toBe(true);
        expect(hit.decisions[0].reason).toBe('scan');

        vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('down'); }));
        const miss = await lookup('8.8.8.8');
        expect(miss.banned).toBe(false);
        expect(miss.error).toBe('down');
    });

    it('blocks on inspect when CrowdSec bans the IP', async () => {
        const guard = createUranoGuard({
            securityMode: 'block_threats',
            crowdsec: {
                inspect: true,
                lookup: async (ip) => ({
                    ip,
                    banned: true,
                    decisions: [{ type: 'ban', reason: 'brute' }]
                })
            }
        });
        const decision = await guard.inspect(ctx({ ip: '5.5.5.5', body: { message: 'hi' } }));
        expect(decision.allowed).toBe(false);
        expect(decision.reason).toBe('CrowdSec decision');
    });

    it('monitor_only never blocks a CrowdSec hit', async () => {
        const guard = createUranoGuard({
            securityMode: 'monitor_only',
            crowdsec: {
                inspect: true,
                lookup: async (ip) => ({ ip, banned: true, decisions: [{ type: 'ban' }] })
            }
        });
        const decision = await guard.inspect(ctx({ ip: '5.5.5.5', body: { message: 'hi' } }));
        expect(decision.allowed).toBe(true);
    });

    it('registers crowdsec.lookup on the agent catalog when configured', async () => {
        const resolved = resolveRemoteAgentConfig({
            remoteAgent: { url: 'https://agent.example/analyze' },
            crowdsec: {
                lookup: async (ip) => ({ ip, banned: false, decisions: [] })
            }
        });
        expect(resolved?.skills?.catalog?.[CROWDSEC_SKILL_NAME]).toBeDefined();
        const skill = createCrowdSecSkill({
            lookup: async (ip) => ({ ip, banned: ip === '7.7.7.7', decisions: [] })
        });
        const result = await skill.provide(
            { ip: '7.7.7.7' },
            ctx({ ip: '1.1.1.1' }),
            { threats: [], maxRiskScore: 0 }
        );
        expect((result as { banned: boolean }).banned).toBe(true);
    });
});
