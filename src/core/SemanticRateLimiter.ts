export interface SemanticRateLimiterOptions {
    windowMs?: number;
    maxRequestsPerWindow?: number;
    campaignIpThreshold?: number;
}

interface RateBucket {
    count: number;
    windowStart: number;
    ips: Set<string>;
}

export type SemanticKey = string;

export class SemanticRateLimiter {
    private buckets = new Map<SemanticKey, RateBucket>();
    private opts: Required<SemanticRateLimiterOptions>;
    private checks = 0;

    constructor(opts: SemanticRateLimiterOptions = {}) {
        this.opts = {
            windowMs: opts.windowMs ?? 60_000,
            maxRequestsPerWindow: opts.maxRequestsPerWindow ?? 60,
            campaignIpThreshold: opts.campaignIpThreshold ?? 20
        };
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

    check(semanticKey: SemanticKey, ip: string): 'ALLOWED' | 'RATE_LIMITED' | 'CAMPAIGN_DETECTED' {
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

    sweep(): void {
        const cutoff = Date.now() - this.opts.windowMs;
        for (const [key, bucket] of this.buckets) {
            if (bucket.windowStart < cutoff) this.buckets.delete(key);
        }
    }
}
