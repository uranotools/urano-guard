import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from '../src/core/CircuitBreaker';
import { MemoryStore } from '../src/core/SharedStore';

describe('CircuitBreaker', () => {
    it('opens after consecutive failures', () => {
        const cb = new CircuitBreaker({ failureThreshold: 2, recoveryTimeMs: 50_000 });
        cb.recordFailure();
        expect(cb.getState()).toBe('CLOSED');
        cb.recordFailure();
        expect(cb.getState()).toBe('OPEN');
        expect(cb.canCallRemote()).toBe(false);
    });

    it('allows a single HALF_OPEN probe', () => {
        const cb = new CircuitBreaker({ failureThreshold: 1, recoveryTimeMs: 0, probeSuccessThreshold: 2 });
        cb.recordFailure();
        expect(cb.getState()).toBe('OPEN');
        expect(cb.canCallRemote()).toBe(true);
        expect(cb.getState()).toBe('HALF_OPEN');
        expect(cb.canCallRemote()).toBe(false);
        cb.recordSuccess(10);
        expect(cb.canCallRemote()).toBe(true);
        cb.recordSuccess(10);
        expect(cb.getState()).toBe('CLOSED');
    });

    it('re-opens if the probe fails', () => {
        const cb = new CircuitBreaker({ failureThreshold: 1, recoveryTimeMs: 0 });
        cb.recordFailure();
        expect(cb.canCallRemote()).toBe(true);
        cb.recordFailure();
        expect(cb.getState()).toBe('OPEN');
    });

    it('shares OPEN across instances and allows only one HALF_OPEN probe', async () => {
        const store = new MemoryStore();
        const opts = {
            store,
            failureThreshold: 1,
            recoveryTimeMs: 0,
            probeSuccessThreshold: 2
        };
        const a = new CircuitBreaker(opts);
        const b = new CircuitBreaker(opts);

        await a.recordFailure();
        expect(await b.getState()).toBe('OPEN');
        expect(await a.getState()).toBe('OPEN');

        const [probeA, probeB] = await Promise.all([a.canCallRemote(), b.canCallRemote()]);
        expect([probeA, probeB].filter(Boolean)).toHaveLength(1);
        expect(await a.getState()).toBe('HALF_OPEN');
        expect(await b.getState()).toBe('HALF_OPEN');

        const winner = probeA ? a : b;
        const loser = probeA ? b : a;
        expect(await loser.canCallRemote()).toBe(false);

        await winner.recordSuccess(10);
        expect(await loser.canCallRemote()).toBe(true);
        await loser.recordSuccess(10);
        expect(await a.getState()).toBe('CLOSED');
        expect(await b.getState()).toBe('CLOSED');
    });

    it('applies concurrent CLOSED failure decrements', async () => {
        const store = new MemoryStore();
        await store.set('ug:cb:state', 'CLOSED', 0);
        await store.set('ug:cb:failures', 4, 0);
        const opts = { store, failureThreshold: 10, recoveryTimeMs: 50_000 };
        const a = new CircuitBreaker(opts);
        const b = new CircuitBreaker(opts);

        await Promise.all([a.recordSuccess(10), b.recordSuccess(10)]);
        expect(await store.get('ug:cb:failures')).toBe(2);
        expect(await a.getState()).toBe('CLOSED');
        expect(await b.getState()).toBe('CLOSED');
    });

    it('lets only one process win OPEN → HALF_OPEN', async () => {
        class CountingCasStore extends MemoryStore {
            casWins = 0;
            async cas<T = unknown>(key: string, expected: T, next: T, ttlMs?: number): Promise<boolean> {
                const won = await super.cas(key, expected, next, ttlMs);
                if (won) this.casWins++;
                return won;
            }
        }
        const store = new CountingCasStore();
        const opts = {
            store,
            failureThreshold: 1,
            recoveryTimeMs: 0,
            probeSuccessThreshold: 2
        };
        const a = new CircuitBreaker(opts);
        const b = new CircuitBreaker(opts);
        await a.recordFailure();
        expect(await store.get('ug:cb:state')).toBe('OPEN');

        const [probeA, probeB] = await Promise.all([a.canCallRemote(), b.canCallRemote()]);
        expect(store.casWins).toBe(1);
        expect([probeA, probeB].filter(Boolean)).toHaveLength(1);
        expect(await store.get('ug:cb:state')).toBe('HALF_OPEN');
        expect(await a.getState()).toBe('HALF_OPEN');
        expect(await b.getState()).toBe('HALF_OPEN');
    });
});
