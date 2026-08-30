import { describe, expect, it } from 'vitest';
import { ReplayGuard } from '../src/core/ReplayGuard';
import { CacheManager } from '../src/core/CacheManager';
import { pickClientIp, pickSenderId } from '../src/utils/identity';

describe('ReplayGuard', () => {
    it('rejects a reused nonce', () => {
        const guard = new ReplayGuard({ timestampWindowMs: 60_000 });
        const headers = {
            'x-urano-timestamp': String(Date.now()),
            'x-urano-nonce': 'abc-1'
        };
        expect(guard.check(headers).valid).toBe(true);
        expect(guard.check(headers).reason).toBe('REPLAY_DETECTED');
    });

    it('rejects expired timestamps', () => {
        const guard = new ReplayGuard({ timestampWindowMs: 1000 });
        const result = guard.check({
            'x-urano-timestamp': String(Date.now() - 10_000),
            'x-urano-nonce': 'abc-2'
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('TIMESTAMP_EXPIRED');
    });
});

describe('CacheManager LRU', () => {
    it('evicts the least recently used entry', () => {
        const cache = new CacheManager(60_000, 2);
        cache.set('a', { allowed: true, action: 'ALLOW', riskScore: 0, threats: [], latencyMs: 0, source: 'LOCAL_INSPECTOR' });
        cache.set('b', { allowed: true, action: 'ALLOW', riskScore: 0, threats: [], latencyMs: 0, source: 'LOCAL_INSPECTOR' });
        cache.get('a');
        cache.set('c', { allowed: false, action: 'BLOCK', riskScore: 1, threats: [], latencyMs: 0, source: 'LOCAL_INSPECTOR' });
        expect(cache.get('a')).not.toBeNull();
        expect(cache.get('b')).toBeNull();
        expect(cache.get('c')?.allowed).toBe(false);
    });
});

describe('trustProxy identity', () => {
    it('ignores forwarded headers unless trustProxy is on', () => {
        const untrusted = pickClientIp({
            trustProxy: false,
            socketIp: '10.0.0.1',
            forwardedFor: '8.8.8.8'
        });
        expect(untrusted).toBe('10.0.0.1');
        const trusted = pickClientIp({
            trustProxy: true,
            socketIp: '10.0.0.1',
            forwardedFor: '8.8.8.8, 1.1.1.1'
        });
        expect(trusted).toBe('8.8.8.8');
        expect(pickSenderId({ trustProxy: false, ip: '10.0.0.1', headerUserId: 'attacker' })).toBe('10.0.0.1');
        expect(pickSenderId({ trustProxy: true, ip: '10.0.0.1', headerUserId: 'user-1' })).toBe('user-1');
    });
});
