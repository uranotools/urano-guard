export interface SemanticRateLimiterOptions {
    /** Ventana de tiempo en ms para agrupar peticiones (default: 60_000 = 1 min) */
    windowMs?: number;
    /** Máximo de peticiones por ventana por identificador semántico (default: 60) */
    maxRequestsPerWindow?: number;
    /** Máximo de IPs distintas que pueden activar el mismo patrón antes de bloquearlo globalmente (default: 20) */
    campaignIpThreshold?: number;
}

interface RateBucket {
    count: number;
    windowStart: number;
    ips: Set<string>;
}

/** 
 * Fingerprint semántico de una petición a limitar.
 * Se calcula a partir del path + método + patrón de palabras clave detectadas.
 */
export type SemanticKey = string;

export class SemanticRateLimiter {
    private buckets = new Map<SemanticKey, RateBucket>();
    private opts: Required<SemanticRateLimiterOptions>;

    constructor(opts: SemanticRateLimiterOptions = {}) {
        this.opts = {
            windowMs: opts.windowMs ?? 60_000,
            maxRequestsPerWindow: opts.maxRequestsPerWindow ?? 60,
            campaignIpThreshold: opts.campaignIpThreshold ?? 20
        };
    }

    /**
     * Genera una clave semántica que identifica la "intención" de la petición
     * en lugar de la IP fuente. Detecta campañas de reconocimiento distribuido.
     */
    buildSemanticKey(method: string, path: string, body: any): SemanticKey {
        const text = typeof body === 'string' ? body : JSON.stringify(body || '');
        const normalizedPath = path.replace(/[0-9a-f-]{8,}/gi, ':id').toLowerCase();

        // Palabras clave de reconocimiento que indican intención de sondeo
        const reconKeywords = ['schema', 'introspect', 'admin', 'password', 'token', 'secret', '.env', 'debug', 'config'];
        const matchedKeyword = reconKeywords.find(kw => text.toLowerCase().includes(kw) || path.toLowerCase().includes(kw));

        return `${method}:${normalizedPath}:${matchedKeyword || 'generic'}`;
    }

    /**
     * Registra una petición y verifica si se supera el límite.
     * Retorna 'ALLOWED', 'RATE_LIMITED', o 'CAMPAIGN_DETECTED'.
     */
    check(semanticKey: SemanticKey, ip: string): 'ALLOWED' | 'RATE_LIMITED' | 'CAMPAIGN_DETECTED' {
        const now = Date.now();
        let bucket = this.buckets.get(semanticKey);

        if (!bucket || (now - bucket.windowStart) > this.opts.windowMs) {
            bucket = { count: 0, windowStart: now, ips: new Set() };
            this.buckets.set(semanticKey, bucket);
        }

        bucket.count++;
        bucket.ips.add(ip);

        // Campaña coordinada: muchas IPs distintas con el mismo patrón semántico
        if (bucket.ips.size >= this.opts.campaignIpThreshold) {
            return 'CAMPAIGN_DETECTED';
        }

        // Límite por identificador semántico individual
        if (bucket.count > this.opts.maxRequestsPerWindow) {
            return 'RATE_LIMITED';
        }

        return 'ALLOWED';
    }

    /** Limpia buckets expirados (llamar periódicamente o en GC). */
    sweep(): void {
        const cutoff = Date.now() - this.opts.windowMs;
        for (const [k, b] of this.buckets) {
            if (b.windowStart < cutoff) this.buckets.delete(k);
        }
    }
}
