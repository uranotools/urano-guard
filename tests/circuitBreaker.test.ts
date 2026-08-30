import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from '../src/core/CircuitBreaker';

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
});
