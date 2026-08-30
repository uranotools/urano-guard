import * as crypto from 'crypto';
import { SharedStore } from '../types/store';

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
 *
 * When a {@link SharedStore} is provided, occurrence counts live at `ug:fp:`
 * (atomic `incr`, no expiry) so processes share them.
 */
export class RequestFingerprinter {
    private local = new Map<string, { count: number; firstSeen: number }>();
    private maxEntries: number;
    private store?: SharedStore;

    constructor(maxEntries = 10_000, store?: SharedStore) {
        this.maxEntries = maxEntries;
        this.store = store;
    }

    /**
     * Genera un fingerprint basado en características de comportamiento
     * (no en IP) para rastrear al atacante incluso si rota sus direcciones.
     */
    fingerprint(headers: Record<string, any>, method: string, path: string, bodySnippet: string): FingerprintResult | Promise<FingerprintResult> {
        const fp = this.hash(headers, method, path, bodySnippet);
        if (this.store) return this.fingerprintStore(fp);
        return this.fingerprintLocal(fp);
    }

    /** Borra el historial de un fingerprint (ej: si se determina falso positivo). */
    clear(fingerprint: string): void | Promise<void> {
        this.local.delete(fingerprint);
        if (this.store) return this.store.delete(`ug:fp:${fingerprint}`);
    }

    private hash(headers: Record<string, any>, method: string, path: string, bodySnippet: string): string {
        const ua = headers['user-agent'] || '';
        const acceptLang = headers['accept-language'] || '';
        const acceptEnc = headers['accept-encoding'] || '';
        const contentType = headers['content-type'] || '';
        const normalizedPath = path.replace(/[0-9a-f-]{8,}/gi, ':id');

        // Combinar características de comportamiento, NO de identidad
        const raw = `${ua}|${acceptLang}|${acceptEnc}|${contentType}|${method}:${normalizedPath}|${bodySnippet.slice(0, 64)}`;
        return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
    }

    private async fingerprintStore(fp: string): Promise<FingerprintResult> {
        const count = await this.store!.incr(`ug:fp:${fp}`, 0);
        return { fingerprint: fp, seenBefore: count > 1, occurrences: count };
    }

    private fingerprintLocal(fp: string): FingerprintResult {
        const existing = this.local.get(fp);
        if (existing) {
            existing.count++;
            return { fingerprint: fp, seenBefore: true, occurrences: existing.count };
        }

        if (this.local.size >= this.maxEntries) {
            // LRU: eliminar la entrada más antigua
            const oldestKey = this.local.keys().next().value;
            if (oldestKey) this.local.delete(oldestKey);
        }

        this.local.set(fp, { count: 1, firstSeen: Date.now() });
        return { fingerprint: fp, seenBefore: false, occurrences: 1 };
    }
}
