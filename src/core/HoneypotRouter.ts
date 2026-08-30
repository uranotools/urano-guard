import { randomToken } from '../utils/crypto';

export interface HoneypotConfig {
    tarpitEnabled?: boolean;
    tarpitDelayMs?: number;
    honeyTokensEnabled?: boolean;
    onHoneyTokenAccessed?: (token: string, context: any) => void;
}

export interface HoneypotDecision {
    strategy: 'TARPIT' | 'HONEY_RESPONSE' | 'SHADOW_ALLOW';
    delayMs: number;
    fakeBody?: any;
    honeyToken?: string;
}

export class HoneypotRouter {
    private config: HoneypotConfig;
    private honeyTokens = new Map<string, { createdAt: number; context: any }>();

    constructor(config: HoneypotConfig = {}) {
        this.config = {
            tarpitEnabled: config.tarpitEnabled ?? true,
            tarpitDelayMs: config.tarpitDelayMs ?? 4_000,
            honeyTokensEnabled: config.honeyTokensEnabled ?? true,
            onHoneyTokenAccessed: config.onHoneyTokenAccessed
        };
    }

    async decide(threatCategory: string, riskScore: number): Promise<HoneypotDecision> {
        const delayMs = this.config.tarpitEnabled ? (this.config.tarpitDelayMs ?? 4_000) : 0;

        if (delayMs > 0) {
            await new Promise(res => setTimeout(res, delayMs));
        }

        if (this.config.honeyTokensEnabled && riskScore >= 70) {
            const token = this.generateHoneyToken();
            const fakeBody = this.generateFakeResponse(threatCategory, token);
            this.honeyTokens.set(token, { createdAt: Date.now(), context: { threatCategory, riskScore } });

            return {
                strategy: 'HONEY_RESPONSE',
                delayMs,
                fakeBody,
                honeyToken: token
            };
        }

        return { strategy: 'TARPIT', delayMs };
    }

    detectHoneyTokenAccess(body: any, headers: Record<string, any>): string | null {
        const text = JSON.stringify(body || '') + JSON.stringify(headers || '');
        for (const [token] of this.honeyTokens) {
            if (text.includes(token)) {
                const ctx = this.honeyTokens.get(token);
                this.config.onHoneyTokenAccessed?.(token, ctx);
                return token;
            }
        }
        return null;
    }

    private generateHoneyToken(): string {
        return randomToken('ht');
    }

    private generateFakeResponse(threatCategory: string, token: string): any {
        const fakes: Record<string, any> = {
            'PROMPT_INJECTION': {
                status: 'processed',
                sessionId: token,
                message: 'Instrucciones recibidas y encoladas para revisión.',
                nextStep: `https://api.trace.urano.cloud/v1/session/${token}`
            },
            'SQL_CMD_INJECTION': {
                status: 'query_success',
                rows: [],
                traceId: token,
                executedAt: new Date().toISOString()
            },
            'SQL_INJECTION': {
                status: 'query_success',
                rows: [],
                traceId: token,
                executedAt: new Date().toISOString()
            },
            'MALICIOUS_URL': {
                status: 'redirect_scheduled',
                redirectId: token,
                eta: '2000ms'
            }
        };

        return fakes[threatCategory] || {
            status: 'ok',
            token,
            timestamp: new Date().toISOString()
        };
    }
}
