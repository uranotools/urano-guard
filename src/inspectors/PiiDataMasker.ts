import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_RE = /(?<![\dA-Za-z])\+[1-9]\d{7,14}(?!\d)/g;
const SECRET_RE = /\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[bp]-[a-zA-Z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b/g;
const CARD_RE = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;

export function luhnValid(digits: string): boolean {
    let sum = 0;
    let alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let n = Number(digits[i]);
        if (alt) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        alt = !alt;
    }
    return sum % 10 === 0;
}

export class PiiDataMasker extends InspectorBase {
    readonly name = 'PiiDataMasker';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(_context: GuardRequestContext): ThreatIncident | null {
        return null;
    }

    sanitize(data: any): any {
        if (!this.enabled) return data;
        if (typeof data === 'string') return this.maskString(data);
        if (data && typeof data === 'object') {
            const copy: any = Array.isArray(data) ? [] : {};
            for (const key of Object.keys(data)) {
                copy[key] = this.sanitize(data[key]);
            }
            return copy;
        }
        return data;
    }

    private maskString(value: string): string {
        return value
            .replace(CARD_RE, (match) => {
                const digits = match.replace(/\D/g, '');
                return luhnValid(digits) ? '[CREDIT_CARD_PROTECTED]' : match;
            })
            .replace(EMAIL_RE, '[EMAIL_PROTECTED]')
            .replace(PHONE_RE, '[PHONE_PROTECTED]')
            .replace(SECRET_RE, '[API_KEY_REDACTED]');
    }
}
