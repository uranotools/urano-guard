import { GuardLogger, MetricsExporter, createSilentLogger } from '../types/logger';
import { SharedStore } from '../types/store';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

const STORE_PREFIX = 'ug:cb:';

export interface CircuitBreakerOptions {
    latencyThresholdMs?: number;
    failureThreshold?: number;
    recoveryTimeMs?: number;
    probeSuccessThreshold?: number;
    logger?: GuardLogger;
    metrics?: MetricsExporter;
    /**
     * When set, OPEN / HALF_OPEN / CLOSED and the in-flight probe lock are
     * stored here (`ug:cb:`) so multiple processes share one circuit.
     * OPEN→HALF_OPEN uses {@link SharedStore.cas}; CLOSED failure decay uses
     * {@link SharedStore.decr}; the in-flight probe still uses {@link SharedStore.setNX}.
     */
    store?: SharedStore;
}

export class CircuitBreaker {
    private state: CircuitState = 'CLOSED';
    private failures = 0;
    private lastFailureTime = 0;
    private probeSuccesses = 0;
    private probeInFlight = false;
    private store?: SharedStore;
    private opts: Required<Omit<CircuitBreakerOptions, 'logger' | 'metrics' | 'store'>> & {
        logger: GuardLogger;
        metrics?: MetricsExporter;
    };

    constructor(opts: CircuitBreakerOptions = {}) {
        this.opts = {
            latencyThresholdMs: opts.latencyThresholdMs ?? 800,
            failureThreshold: opts.failureThreshold ?? 5,
            recoveryTimeMs: opts.recoveryTimeMs ?? 30_000,
            probeSuccessThreshold: opts.probeSuccessThreshold ?? 3,
            logger: opts.logger ?? createSilentLogger(),
            metrics: opts.metrics
        };
        this.store = opts.store;
        this.syncGauge();
    }

    /**
     * Last observed state. With a store this is a live read (Promise);
     * without a store it is the in-process field.
     */
    getState(): CircuitState | Promise<CircuitState> {
        if (this.store) return this.loadState();
        return this.state;
    }

    recordFailure(): void | Promise<void> {
        if (this.store) return this.recordFailureStore();
        this.probeInFlight = false;
        this.failures++;
        this.lastFailureTime = Date.now();
        if (this.state === 'HALF_OPEN' || this.failures >= this.opts.failureThreshold) {
            this.state = 'OPEN';
            this.probeSuccesses = 0;
            this.opts.logger.warn('Circuit breaker OPEN — falling back to local heuristics');
            this.syncGauge();
        }
    }

    recordSuccess(latencyMs: number): void | Promise<void> {
        if (this.store) return this.recordSuccessStore(latencyMs);
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
                this.syncGauge();
            }
        } else if (this.state === 'CLOSED') {
            this.failures = Math.max(0, this.failures - 1);
        }
    }

    canCallRemote(): boolean | Promise<boolean> {
        if (this.store) return this.canCallRemoteStore();
        if (this.state === 'CLOSED') return true;

        if (this.state === 'OPEN') {
            const elapsed = Date.now() - this.lastFailureTime;
            if (elapsed >= this.opts.recoveryTimeMs) {
                this.state = 'HALF_OPEN';
                this.probeSuccesses = 0;
                this.opts.logger.info('Circuit breaker HALF_OPEN — sending a single probe');
                this.syncGauge();
            } else {
                return false;
            }
        }

        if (this.probeInFlight) return false;
        this.probeInFlight = true;
        return true;
    }

    private async loadState(): Promise<CircuitState> {
        const raw = await this.store!.get<CircuitState>(`${STORE_PREFIX}state`);
        const state = raw === 'OPEN' || raw === 'HALF_OPEN' || raw === 'CLOSED' ? raw : 'CLOSED';
        this.state = state;
        return state;
    }

    private async canCallRemoteStore(): Promise<boolean> {
        const state = await this.loadState();
        if (state === 'CLOSED') return true;

        if (state === 'OPEN') {
            const last = (await this.store!.get<number>(`${STORE_PREFIX}lastFailure`)) ?? 0;
            if (Date.now() - last >= this.opts.recoveryTimeMs) {
                const won = await this.store!.cas(`${STORE_PREFIX}state`, 'OPEN', 'HALF_OPEN', 0);
                if (won) {
                    await this.store!.set(`${STORE_PREFIX}probeSuccesses`, 0, 0);
                    this.state = 'HALF_OPEN';
                    this.opts.logger.info('Circuit breaker HALF_OPEN — sending a single probe');
                    this.syncGauge();
                } else {
                    const now = await this.loadState();
                    if (now === 'CLOSED') return true;
                    if (now !== 'HALF_OPEN') return false;
                }
            } else {
                return false;
            }
        }

        const probeTtl = Math.max(this.opts.recoveryTimeMs, 5_000);
        return this.store!.setNX(`${STORE_PREFIX}probeLock`, 1, probeTtl);
    }

    private async recordFailureStore(): Promise<void> {
        await this.store!.delete(`${STORE_PREFIX}probeLock`);
        const failures = await this.store!.incr(`${STORE_PREFIX}failures`, 0);
        await this.store!.set(`${STORE_PREFIX}lastFailure`, Date.now(), 0);
        const current = await this.loadState();
        if (current === 'HALF_OPEN' || failures >= this.opts.failureThreshold) {
            await this.store!.set(`${STORE_PREFIX}state`, 'OPEN', 0);
            await this.store!.set(`${STORE_PREFIX}probeSuccesses`, 0, 0);
            this.state = 'OPEN';
            this.opts.logger.warn('Circuit breaker OPEN — falling back to local heuristics');
            this.syncGauge();
        }
    }

    private async recordSuccessStore(latencyMs: number): Promise<void> {
        await this.store!.delete(`${STORE_PREFIX}probeLock`);
        if (latencyMs > this.opts.latencyThresholdMs) {
            await this.recordFailureStore();
            return;
        }
        const state = await this.loadState();
        if (state === 'HALF_OPEN') {
            const n = await this.store!.incr(`${STORE_PREFIX}probeSuccesses`, 0);
            if (n >= this.opts.probeSuccessThreshold) {
                await this.store!.set(`${STORE_PREFIX}state`, 'CLOSED', 0);
                await this.store!.set(`${STORE_PREFIX}failures`, 0, 0);
                await this.store!.set(`${STORE_PREFIX}probeSuccesses`, 0, 0);
                this.state = 'CLOSED';
                this.failures = 0;
                this.probeSuccesses = 0;
                this.opts.logger.info('Circuit breaker CLOSED — remote agent recovered');
                this.syncGauge();
            }
        } else if (state === 'CLOSED') {
            await this.store!.decr(`${STORE_PREFIX}failures`);
        }
    }

    private syncGauge(): void {
        const code = this.state === 'CLOSED' ? 0 : this.state === 'HALF_OPEN' ? 1 : 2;
        this.opts.metrics?.gauge?.('circuitState', code, { state: this.state });
    }
}
