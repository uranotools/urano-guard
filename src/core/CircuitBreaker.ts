import { GuardLogger, createSilentLogger } from '../types/logger';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
    latencyThresholdMs?: number;
    failureThreshold?: number;
    recoveryTimeMs?: number;
    probeSuccessThreshold?: number;
    logger?: GuardLogger;
}

export class CircuitBreaker {
    private state: CircuitState = 'CLOSED';
    private failures = 0;
    private lastFailureTime = 0;
    private probeSuccesses = 0;
    private probeInFlight = false;
    private opts: Required<Omit<CircuitBreakerOptions, 'logger'>> & { logger: GuardLogger };

    constructor(opts: CircuitBreakerOptions = {}) {
        this.opts = {
            latencyThresholdMs: opts.latencyThresholdMs ?? 800,
            failureThreshold: opts.failureThreshold ?? 5,
            recoveryTimeMs: opts.recoveryTimeMs ?? 30_000,
            probeSuccessThreshold: opts.probeSuccessThreshold ?? 3,
            logger: opts.logger ?? createSilentLogger()
        };
    }

    getState(): CircuitState { return this.state; }

    recordFailure(): void {
        this.probeInFlight = false;
        this.failures++;
        this.lastFailureTime = Date.now();
        if (this.state === 'HALF_OPEN' || this.failures >= this.opts.failureThreshold) {
            this.state = 'OPEN';
            this.probeSuccesses = 0;
            this.opts.logger.warn('Circuit breaker OPEN — falling back to local heuristics');
        }
    }

    recordSuccess(latencyMs: number): void {
        this.probeInFlight = false;
        if (latencyMs > this.opts.latencyThresholdMs) {
            this.recordFailure();
            return;
        }
        if (this.state === 'HALF_OPEN') {
            this.probeSuccesses++;
            if (this.probeSuccesses >= this.opts.probeSuccessThreshold) {
                this.state = 'CLOSED';
                this.failures = 0;
                this.probeSuccesses = 0;
                this.opts.logger.info('Circuit breaker CLOSED — remote agent recovered');
            }
        } else if (this.state === 'CLOSED') {
            this.failures = Math.max(0, this.failures - 1);
        }
    }

    canCallRemote(): boolean {
        if (this.state === 'CLOSED') return true;

        if (this.state === 'OPEN') {
            const elapsed = Date.now() - this.lastFailureTime;
            if (elapsed >= this.opts.recoveryTimeMs) {
                this.state = 'HALF_OPEN';
                this.probeSuccesses = 0;
                this.opts.logger.info('Circuit breaker HALF_OPEN — sending a single probe');
            } else {
                return false;
            }
        }

        if (this.probeInFlight) return false;
        this.probeInFlight = true;
        return true;
    }
}
