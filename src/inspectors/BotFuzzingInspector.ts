import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { collectInspectionText, headerValue, stringifySafe } from '../utils/inspectText';

const SCANNER_UA = /sqlmap|nikto|nmap|wfuzz|ffuf|dirbuster|gobuster|w3af|burp|owasp\s*zap|masscan/i;
const PROBE_PATH = /\/(\.env|wp-admin|phpmyadmin|adminer|cgi-bin|\.git)(\b|\/)/i;

function looksLikeJwt(text: string): boolean {
    return /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(text.trim());
}

function looksLikeJson(text: string): boolean {
    const trimmed = text.trim();
    if (!(trimmed.startsWith('{') || trimmed.startsWith('['))) return false;
    try {
        JSON.parse(trimmed);
        return true;
    } catch {
        return false;
    }
}

function looksLikeBase64Blob(text: string): boolean {
    const compact = text.replace(/\s+/g, '');
    return compact.length > 400 && /^[A-Za-z0-9+/=]+$/.test(compact);
}

export class BotFuzzingInspector extends InspectorBase {
    readonly name = 'BotFuzzingInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;

        const bodyText = typeof context.body === 'string' ? context.body : stringifySafe(context.body);
        const ua = headerValue(context.headers, 'user-agent');
        const path = context.path || '';
        const hasRepetitiveBurst = /(.)\1{40,}/.test(collectInspectionText(context));
        const scannerUa = SCANNER_UA.test(ua);
        const probePath = PROBE_PATH.test(path);

        const highEntropy = bodyText.length > 400 && !bodyText.includes(' ');
        const benignBlob = looksLikeJwt(bodyText) || looksLikeJson(bodyText) || looksLikeBase64Blob(bodyText);
        const entropySignal = highEntropy && !benignBlob;

        let signals = 0;
        if (entropySignal) signals++;
        if (hasRepetitiveBurst) signals++;
        if (scannerUa) signals++;
        if (probePath) signals++;

        if (signals < 2) return null;

        return [{
            id: newIncidentId('thr_bot'),
            category: 'BOT_FUZZING',
            severity: 'HIGH',
            riskScore: 65,
            summary: 'Anomalous payload matching automated scanner / fuzzing patterns',
            detectedAt: new Date().toISOString(),
            sender: context.senderId || context.ip,
            details: { signals, scannerUa, probePath, entropySignal, hasRepetitiveBurst }
        }];
    }
}
