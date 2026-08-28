import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

export class BotFuzzingInspector extends InspectorBase {
    readonly name = 'BotFuzzingInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident | null {
        if (!this.enabled) return null;
        const text = typeof context.body === 'string' ? context.body : JSON.stringify(context.body || '');

        // Alta entropía sin espacios (típico de payloads binarios o fuzzers)
        const isHighEntropy = text.length > 400 && !text.includes(' ');
        // Repetición masiva de caracteres
        const hasRepetitiveBurst = /(.)\1{40,}/.test(text);

        if (isHighEntropy || hasRepetitiveBurst) {
            return {
                id: `thr_bot_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
                category: 'BOT_FUZZING',
                severity: 'MEDIUM',
                riskScore: 50,
                summary: 'Patrón anómalo de payload con características de bot / fuzzing automatizado',
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip
            };
        }
        return null;
    }
}