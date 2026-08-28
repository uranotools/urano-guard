import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

export class PiiDataMasker extends InspectorBase {
    readonly name = 'PiiDataMasker';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident | null {
        // PiiDataMasker actúa primariamente como transformador/sanitizador
        return null;
    }

    sanitize(data: any): any {
        if (typeof data === 'string') {
            return data
                .replace(/\b(?:\d{4}[ -]?){3}\d{4}\b/g, '[CREDIT_CARD_PROTECTED]')
                .replace(/(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36})/g, '[API_KEY_REDACTED]');
        }
        if (data && typeof data === 'object') {
            const copy = Array.isArray(data) ? [...data] : { ...data };
            for (const key of Object.keys(copy)) {
                copy[key] = this.sanitize(copy[key]);
            }
            return copy;
        }
        return data;
    }
}