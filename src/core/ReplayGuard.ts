import { GuardLogger, createSilentLogger } from '../types/logger';

export interface ReplayGuardOptions {
    timestampWindowMs?: number;
    maxNonces?: number;
    logger?: GuardLogger;
}

export interface ReplayCheckResult {
    valid: boolean;
    reason?: 'MISSING_TIMESTAMP' | 'TIMESTAMP_EXPIRED' | 'REPLAY_DETECTED' | 'MISSING_NONCE';
}

export class ReplayGuard {
    private usedNonces: Map<string, number>;
    private windowMs: number;
    private maxNonces: number;
    private logger: GuardLogger;
    private lastSweep = 0;

    constructor(opts: ReplayGuardOptions = {}) {
        this.windowMs = opts.timestampWindowMs ?? 300_000;
        this.maxNonces = opts.maxNonces ?? 20_000;
        this.usedNonces = new Map();
        this.logger = opts.logger ?? createSilentLogger();
    }

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

        this.usedNonces.set(nonceStr, now);
        this.sweepExpired(now);
        return { valid: true };
    }

    private sweepExpired(now: number): void {
        if (now - this.lastSweep < 1_000 && this.usedNonces.size < this.maxNonces) return;
        this.lastSweep = now;
        const cutoff = now - this.windowMs;
        for (const [key, value] of this.usedNonces) {
            if (value < cutoff) this.usedNonces.delete(key);
        }
        if (this.usedNonces.size > this.maxNonces) {
            const overflow = this.usedNonces.size - this.maxNonces;
            let removed = 0;
            for (const key of this.usedNonces.keys()) {
                this.usedNonces.delete(key);
                removed++;
                if (removed >= overflow) break;
            }
            this.logger.warn(`Replay nonce store trimmed by ${removed} entries`);
        }
    }
}
