export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
    /** Latencia máxima en ms antes de abrir el circuito (default: 800) */
    latencyThresholdMs?: number;
    /** Número de fallos consecutivos antes de abrir el circuito (default: 5) */
    failureThreshold?: number;
    /** Tiempo en ms hasta intentar recuperación HALF_OPEN (default: 30000) */
    recoveryTimeMs?: number;
    /** Número de pruebas en HALF_OPEN que deben ser exitosas para cerrar (default: 3) */
    probeSuccessThreshold?: number;
}

export class CircuitBreaker {
    private state: CircuitState = 'CLOSED';
    private failures = 0;
    private lastFailureTime = 0;
    private probeSuccesses = 0;
    private opts: Required<CircuitBreakerOptions>;

    constructor(opts: CircuitBreakerOptions = {}) {
        this.opts = {
            latencyThresholdMs: opts.latencyThresholdMs ?? 800,
            failureThreshold: opts.failureThreshold ?? 5,
            recoveryTimeMs: opts.recoveryTimeMs ?? 30_000,
            probeSuccessThreshold: opts.probeSuccessThreshold ?? 3
        };
    }

    getState(): CircuitState { return this.state; }

    /** Llama si el upstream respondió lento o con error. */
    recordFailure(): void {
        this.failures++;
        this.lastFailureTime = Date.now();
        if (this.state === 'HALF_OPEN' || this.failures >= this.opts.failureThreshold) {
            this.state = 'OPEN';
            this.probeSuccesses = 0;
            console.warn(`[UranoGuard CircuitBreaker] Estado: OPEN. Fallback a modo heurístico local.`);
        }
    }

    /** Llama si el upstream respondió con éxito dentro del tiempo umbral. */
    recordSuccess(latencyMs: number): void {
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
                console.info(`[UranoGuard CircuitBreaker] Estado: CLOSED. Servicio recuperado.`);
            }
        } else if (this.state === 'CLOSED') {
            this.failures = Math.max(0, this.failures - 1);
        }
    }

    /**
     * Devuelve true si el circuito PERMITE llamar al upstream.
     * Implementa la transición automática OPEN → HALF_OPEN tras recoveryTimeMs.
     */
    canCallRemote(): boolean {
        if (this.state === 'CLOSED') return true;

        if (this.state === 'OPEN') {
            const elapsed = Date.now() - this.lastFailureTime;
            if (elapsed >= this.opts.recoveryTimeMs) {
                this.state = 'HALF_OPEN';
                this.probeSuccesses = 0;
                console.info(`[UranoGuard CircuitBreaker] Estado: HALF_OPEN. Iniciando prueba de recuperación.`);
                return true; // Permite una sola petición de prueba
            }
            return false; // Circuito abierto, modo local activado
        }

        // HALF_OPEN: solo deja pasar 1 petición de sonda a la vez
        return true;
    }
}
