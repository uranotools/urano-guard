import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

const TAIL_SCAN_BYTES = 4096;    // Inspeccionar últimos 4 KB del payload
const HEAD_SCAN_BYTES = 4096;    // Inspeccionar primeros 4 KB
const PADDING_THRESHOLD = 8192;  // Payloads > 8 KB activan la inspección de cola
const RANDOM_SAMPLE_SIZE = 2048; // Bytes aleatorios del medio a escanear

const INJECTION_TAIL_PATTERNS = [
    /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
    /;\s*(DROP|DELETE|ALTER)\s+TABLE/i,
    /UNION\s+SELECT\s+.*FROM/i,
    /\/etc\/(shadow|passwd)/i,
    /exec\s*\(/i,
    /<script[\s\S]*?>/i
];

export class PaddingEvasionInspector extends InspectorBase {
    readonly name = 'PaddingEvasionInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident | null {
        if (!this.enabled) return null;

        const raw = context.rawBody || (typeof context.body === 'string' ? context.body : JSON.stringify(context.body || ''));

        // Solo activar para payloads grandes donde el padding puede ser efectivo
        if (raw.length <= PADDING_THRESHOLD) return null;

        const head = raw.slice(0, HEAD_SCAN_BYTES);
        const tail = raw.slice(-TAIL_SCAN_BYTES);

        // Muestra aleatoria del centro (detecta evasión por distribución del payload)
        const midStart = Math.max(HEAD_SCAN_BYTES, Math.floor(raw.length / 2) - RANDOM_SAMPLE_SIZE / 2);
        const mid = raw.slice(midStart, midStart + RANDOM_SAMPLE_SIZE);

        // El head generalmente ya fue inspeccionado por otros inspectores.
        // Aquí nos enfocamos en TAIL y MID que evasores de primera capa ignoran.
        for (const pattern of INJECTION_TAIL_PATTERNS) {
            if (pattern.test(tail) || pattern.test(mid)) {
                const location = pattern.test(tail) ? 'TAIL' : 'MIDDLE';
                return {
                    id: `thr_pad_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
                    category: 'PROMPT_INJECTION',
                    severity: 'CRITICAL',
                    riskScore: 92,
                    summary: `Ataque de Padding Evasion detectado en ${location} del payload (${raw.length} bytes). El payload incrustó código malicioso al final para evadir inspectores de encabezado.`,
                    matchedPattern: pattern.toString(),
                    detectedAt: new Date().toISOString(),
                    sender: context.senderId || context.ip,
                    details: {
                        totalPayloadBytes: raw.length,
                        detectedLocation: location,
                        tailSample: tail.slice(0, 200)
                    }
                };
            }
        }

        return null;
    }
}
