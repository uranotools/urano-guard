export interface HoneypotConfig {
    /** Activa el modo tarpit: retarda la respuesta del atacante para gastar sus recursos */
    tarpitEnabled?: boolean;
    /** Retardo en ms para respuestas tarpit (default: 4000) */
    tarpitDelayMs?: number;
    /** Genera honey-tokens falsos para rastrear al atacante en sus intentos */
    honeyTokensEnabled?: boolean;
    /** Función opcional para notificar acceso a honey-token (telemetría SOC) */
    onHoneyTokenAccessed?: (token: string, context: any) => void;
}

export interface HoneypotDecision {
    strategy: 'TARPIT' | 'HONEY_RESPONSE' | 'SHADOW_ALLOW';
    /** Delay artificially applied in ms */
    delayMs: number;
    /** Si es honey response, el body falso a retornar */
    fakeBody?: any;
    /** Token de rastreo insertado en la respuesta */
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

    /**
     * Genera una decisión de honeypot para un atacante detectado.
     * La idea es no rechazar de inmediato con 403 (lo cual enseña al atacante),
     * sino retardarlo, rastrearlo o responderle con datos falsos.
     */
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

        return {
            strategy: 'TARPIT',
            delayMs
        };
    }

    /**
     * Detecta si una petición contiene un honey-token (el atacante regresó con datos robados).
     */
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
        return `ht_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
    }

    private generateFakeResponse(threatCategory: string, token: string): any {
        // Respuestas falsas realistas según el tipo de amenaza detectada
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
