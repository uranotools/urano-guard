import { SharedStore } from './SharedStore';

export interface SemanticRateLimiterOptions {
    windowMs?: number;
    maxRequestsPerWindow?: number;
    campaignIpThreshold?: number;
    store?: SharedStore;
}

interface RateBucket {
    count: number;
    windowStart: number;
    ips: Set<string>;
}

export type SemanticKey = string;

/**
 * Semantic (path + recon-keyword) rate limiter.
 *
 * Store-backed counts use atomic `incr` (`ug:rl:count:`). Unique IPs use
 * `sadd` (`ug:rl:ips:`) so concurrent writers cannot drop members or slide
 * the window TTL.
 */
export class SemanticRateLimiter {
    private buckets = new Map<SemanticKey, RateBucket>();
    private opts: Required<Omit<SemanticRateLimiterOptions, 'store'>>;
    private store?: SharedStore;
    private checks = 0;

    constructor(opts: SemanticRateLimiterOptions = {}) {
        this.opts = {
            windowMs: opts.windowMs ?? 60_000,
            maxRequestsPerWindow: opts.maxRequestsPerWindow ?? 60,
            campaignIpThreshold: opts.campaignIpThreshold ?? 20
        };
        this.store = opts.store;
    }

    buildSemanticKey(method: string, path: string, body: any): SemanticKey {
        const text = typeof body === 'string' ? body : JSON.stringify(body || '');
        const normalizedPath = path.replace(/[0-9a-f-]{8,}/gi, ':id').toLowerCase();
        const reconKeywords = ['schema', 'introspect', 'admin', 'token', 'secret', '.env', 'debug', 'config'];
        const matchedKeyword = reconKeywords.find(kw =>
            text.toLowerCase().includes(kw) || path.toLowerCase().includes(kw)
        );
        return `${method}:${normalizedPath}:${matchedKeyword || 'generic'}`;
    }

    check(semanticKey: SemanticKey, ip: string): 'ALLOWED' | 'RATE_LIMITED' | 'CAMPAIGN_DETECTED' | Promise<'ALLOWED' | 'RATE_LIMITED' | 'CAMPAIGN_DETECTED'> {
        if (this.store) return this.checkStore(semanticKey, ip);

        const now = Date.now();
        this.checks++;
        if (this.checks % 32 === 0 || this.buckets.size > 2_000) {
            this.sweep();
        }

        let bucket = this.buckets.get(semanticKey);

        if (!bucket || (now - bucket.windowStart) > this.opts.windowMs) {
            bucket = { count: 0, windowStart: now, ips: new Set() };
            this.buckets.set(semanticKey, bucket);
        }

        bucket.count++;
        bucket.ips.add(ip);

        if (bucket.ips.size >= this.opts.campaignIpThreshold) {
            return 'CAMPAIGN_DETECTED';
        }
        if (bucket.count > this.opts.maxRequestsPerWindow) {
            return 'RATE_LIMITED';
        }
        return 'ALLOWED';
    }

    /**
     * Count is atomic (`incr`). Unique IPs use `sadd` so two processes cannot
     * overwrite each other's member list. TTL is applied only when the set
     * has no expiry (window does not slide).
     */
    private async checkStore(semanticKey: SemanticKey, ip: string): Promise<'ALLOWED' | 'RATE_LIMITED' | 'CAMPAIGN_DETECTED'> {
        const count = await this.store!.incr(`ug:rl:count:${semanticKey}`, this.opts.windowMs);
        const ipsKey = `ug:rl:ips:${semanticKey}`;
        await this.store!.sadd(ipsKey, ip, this.opts.windowMs);
        const ips = await this.store!.smembers(ipsKey);
        if (ips.length >= this.opts.campaignIpThreshold) {
            return 'CAMPAIGN_DETECTED';
        }
        if (count > this.opts.maxRequestsPerWindow) {
            return 'RATE_LIMITED';
        }
        return 'ALLOWED';
    }

    sweep(): void {
        const cutoff = Date.now() - this.opts.windowMs;
        for (const [key, bucket] of this.buckets) {
            if (bucket.windowStart < cutoff) this.buckets.delete(key);
        }
    }
}
