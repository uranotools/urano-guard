export interface ReplayGuardOptions {
    /** Ventana de tolerancia de tiempo en ms (default: 300_000 = 5 min) */
    timestampWindowMs?: number;
    /** Tamaño máximo del cache de nonces en memoria (default: 20000) */
    maxNonces?: number;
}

export interface ReplayCheckResult {
    valid: boolean;
    reason?: 'MISSING_TIMESTAMP' | 'TIMESTAMP_EXPIRED' | 'REPLAY_DETECTED' | 'MISSING_NONCE';
}

export class ReplayGuard {
    private usedNonces: Map<string, number>; // nonce -> timestamp de uso
    private windowMs: number;
    private maxNonces: number;

    constructor(opts: ReplayGuardOptions = {}) {
        this.windowMs = opts.timestampWindowMs ?? 300_000;
        this.maxNonces = opts.maxNonces ?? 20_000;
        this.usedNonces = new Map();
    }

    /**
     * Valida que el timestamp sea reciente y que el nonce no haya sido visto antes.
     * Cabeceras esperadas: x-urano-timestamp (epoch ms), x-urano-nonce (UUID o token único).
     */
    check(headers: Record<string, string | string[] | undefined>): ReplayCheckResult {
        const rawTs = headers['x-urano-timestamp'] || headers['x-timestamp'];
        const nonce = headers['x-urano-nonce'] || headers['x-nonce'];

        if (!rawTs) return { valid: false, reason: 'MISSING_TIMESTAMP' };
        if (!nonce) return { valid: false, reason: 'MISSING_NONCE' };

        const ts = Number(Array.isArray(rawTs) ? rawTs[0] : rawTs);
        const now = Date.now();

        if (isNaN(ts) || Math.abs(now - ts) > this.windowMs) {
            return { valid: false, reason: 'TIMESTAMP_EXPIRED' };
        }

        const nonceStr = String(Array.isArray(nonce) ? nonce[0] : nonce);
        if (this.usedNonces.has(nonceStr)) {
            return { valid: false, reason: 'REPLAY_DETECTED' };
        }

        // Registrar el nonce y limpiar los expirados (LRU ligero)
        this.usedNonces.set(nonceStr, now);
        this.sweepExpired(now);

        return { valid: true };
    }

    private sweepExpired(now: number): void {
        if (this.usedNonces.size < this.maxNonces) return;
        const cutoff = now - this.windowMs;
        for (const [k, v] of this.usedNonces) {
            if (v < cutoff) this.usedNonces.delete(k);
            if (this.usedNonces.size < this.maxNonces * 0.8) break;
        }
    }
}
