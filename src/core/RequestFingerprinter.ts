import * as crypto from 'crypto';

export interface FingerprintResult {
    fingerprint: string;
    /** Indica si esta "firma de comportamiento" fue vista antes en la sesión */
    seenBefore: boolean;
    /** Número de veces que se ha visto este comportamiento */
    occurrences: number;
}

/**
 * Genera y rastrea fingerprints de comportamiento de atacantes
 * para detectar variantes del mismo agente adversarial aunque cambie de IP.
 */
export class RequestFingerprinter {
    private store = new Map<string, { count: number; firstSeen: number }>();
    private maxEntries: number;

    constructor(maxEntries = 10_000) {
        this.maxEntries = maxEntries;
    }

    /**
     * Genera un fingerprint basado en características de comportamiento
     * (no en IP) para rastrear al atacante incluso si rota sus direcciones.
     */
    fingerprint(headers: Record<string, any>, method: string, path: string, bodySnippet: string): FingerprintResult {
        const ua = headers['user-agent'] || '';
        const acceptLang = headers['accept-language'] || '';
        const acceptEnc = headers['accept-encoding'] || '';
        const contentType = headers['content-type'] || '';
        const normalizedPath = path.replace(/[0-9a-f-]{8,}/gi, ':id');

        // Combinar características de comportamiento, NO de identidad
        const raw = `${ua}|${acceptLang}|${acceptEnc}|${contentType}|${method}:${normalizedPath}|${bodySnippet.slice(0, 64)}`;
        const fp = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);

        const existing = this.store.get(fp);
        if (existing) {
            existing.count++;
            return { fingerprint: fp, seenBefore: true, occurrences: existing.count };
        }

        if (this.store.size >= this.maxEntries) {
            // LRU: eliminar la entrada más antigua
            const oldestKey = this.store.keys().next().value;
            if (oldestKey) this.store.delete(oldestKey);
        }

        this.store.set(fp, { count: 1, firstSeen: Date.now() });
        return { fingerprint: fp, seenBefore: false, occurrences: 1 };
    }

    /** Borra el historial de un fingerprint (ej: si se determina falso positivo). */
    clear(fingerprint: string): void {
        this.store.delete(fingerprint);
    }
}
