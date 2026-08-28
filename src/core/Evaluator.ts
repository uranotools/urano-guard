import { GuardRequestContext, SecurityDecision } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { UranoGuardConfig } from '../types/config';
import { ThreatRegistry } from './ThreatRegistry';
import { CacheManager } from './CacheManager';
import { CircuitBreaker } from './CircuitBreaker';
import { ReplayGuard } from './ReplayGuard';
import { SemanticRateLimiter } from './SemanticRateLimiter';
import { RequestFingerprinter } from './RequestFingerprinter';
import { InspectorBase } from '../inspectors/InspectorBase';
import { PiiDataMasker } from '../inspectors/PiiDataMasker';

export class Evaluator {
    private config: UranoGuardConfig;
    private registry: ThreatRegistry;
    private cache: CacheManager;
    private inspectors: InspectorBase[];
    private piiMasker: PiiDataMasker;
    private circuitBreaker?: CircuitBreaker;
    private replayGuard?: ReplayGuard;
    private rateLimiter?: SemanticRateLimiter;
    private fingerprinter?: RequestFingerprinter;

    constructor(
        config: UranoGuardConfig,
        registry: ThreatRegistry,
        cache: CacheManager,
        inspectors: InspectorBase[]
    ) {
        this.config = config;
        this.registry = registry;
        this.cache = cache;
        this.inspectors = inspectors;
        this.piiMasker = new PiiDataMasker(config.inspectors?.piiDataMasking !== false);

        if (config.circuitBreaker?.enabled !== false) {
            this.circuitBreaker = new CircuitBreaker({
                latencyThresholdMs: config.circuitBreaker?.latencyThresholdMs,
                failureThreshold: config.circuitBreaker?.failureThreshold,
                recoveryTimeMs: config.circuitBreaker?.recoveryTimeMs
            });
        }

        if (config.replayGuard?.enabled) {
            this.replayGuard = new ReplayGuard({
                timestampWindowMs: config.replayGuard?.timestampWindowMs
            });
        }

        if (config.semanticRateLimit?.enabled) {
            this.rateLimiter = new SemanticRateLimiter({
                windowMs: config.semanticRateLimit?.windowMs,
                maxRequestsPerWindow: config.semanticRateLimit?.maxRequestsPerWindow,
                campaignIpThreshold: config.semanticRateLimit?.campaignIpThreshold
            });
        }

        if (config.fingerprinting?.enabled) {
            this.fingerprinter = new RequestFingerprinter();
        }
    }

    async evaluate(context: GuardRequestContext): Promise<SecurityDecision> {
        const start = Date.now();
        const senderId = context.senderId || context.ip;

        // 1. Whitelist — Bypass instantáneo y total
        if (this.registry.isWhitelisted(senderId)) {
            return this.allow(start, 'LOCAL_INSPECTOR');
        }

        // 2. Blacklist — Bloqueo instantáneo
        if (this.registry.isBlacklisted(senderId)) {
            return this.block(start, 100, [{
                id: `thr_blk_${Date.now()}`,
                category: 'BLACKLISTED',
                severity: 'CRITICAL',
                riskScore: 100,
                summary: `Remitente ${senderId} en lista negra de ciberdefensa.`,
                detectedAt: new Date().toISOString(),
                sender: senderId
            }], 'Remitente en lista negra', 'LOCAL_INSPECTOR');
        }

        // 3. Anti-Replay (Nonce + Timestamp)
        if (this.replayGuard) {
            const replayCheck = this.replayGuard.check(context.headers as any);
            if (!replayCheck.valid) {
                const isStrict = this.config.replayGuard?.strict === true;
                const incident: ThreatIncident = {
                    id: `thr_replay_${Date.now()}`,
                    category: 'CUSTOM',
                    severity: isStrict ? 'HIGH' : 'MEDIUM',
                    riskScore: isStrict ? 80 : 40,
                    summary: `Protección Anti-Replay activada: ${replayCheck.reason}`,
                    detectedAt: new Date().toISOString(),
                    sender: senderId
                };
                if (isStrict) {
                    return this.block(start, 80, [incident], replayCheck.reason, 'LOCAL_INSPECTOR');
                }
                // No-strict: solo registra pero deja pasar con advertencia
                console.warn(`[UranoGuard ReplayGuard] ${replayCheck.reason} desde ${senderId}`);
            }
        }

        // 4. Fingerprinting de comportamiento
        if (this.fingerprinter) {
            const bodySnippet = typeof context.body === 'string' ? context.body : JSON.stringify(context.body || '');
            const fp = this.fingerprinter.fingerprint(context.headers as any, context.method, context.path, bodySnippet);
            const threshold = this.config.fingerprinting?.suspiciousThreshold ?? 10;

            if (fp.seenBefore && fp.occurrences >= threshold) {
                return this.block(start, 75, [{
                    id: `thr_fp_${Date.now()}`,
                    category: 'BOT_FUZZING',
                    severity: 'HIGH',
                    riskScore: 75,
                    summary: `Atacante persistente detectado por fingerprint: ${fp.fingerprint} (${fp.occurrences} solicitudes con el mismo patrón de comportamiento).`,
                    detectedAt: new Date().toISOString(),
                    sender: senderId,
                    details: { fingerprint: fp.fingerprint, occurrences: fp.occurrences }
                }], 'Patrón de comportamiento repetitivo detectado', 'LOCAL_INSPECTOR');
            }
        }

        // 5. Semantic Rate Limiter
        if (this.rateLimiter) {
            const bodyStr = typeof context.body === 'string' ? context.body : JSON.stringify(context.body || '');
            const semanticKey = this.rateLimiter.buildSemanticKey(context.method, context.path, bodyStr);
            const rateResult = this.rateLimiter.check(semanticKey, context.ip);

            if (rateResult === 'CAMPAIGN_DETECTED') {
                return this.block(start, 85, [{
                    id: `thr_campaign_${Date.now()}`,
                    category: 'BOT_FUZZING',
                    severity: 'CRITICAL',
                    riskScore: 85,
                    summary: `Campaña de reconocimiento distribuido detectada en patrón semántico: ${semanticKey}. Múltiples IPs atacando coordinadamente.`,
                    detectedAt: new Date().toISOString(),
                    sender: senderId
                }], 'Campaña coordinada detectada', 'LOCAL_INSPECTOR');
            }

            if (rateResult === 'RATE_LIMITED') {
                return this.block(start, 60, [{
                    id: `thr_rl_${Date.now()}`,
                    category: 'BOT_FUZZING',
                    severity: 'HIGH',
                    riskScore: 60,
                    summary: `Límite semántico superado para patrón: ${semanticKey}`,
                    detectedAt: new Date().toISOString(),
                    sender: senderId
                }], 'Rate limit semántico excedido', 'LOCAL_INSPECTOR');
            }
        }

        // 6. Caché de Veredictos
        const cacheKey = `${senderId}_${context.method}_${context.path}_${JSON.stringify(context.body || '').slice(0, 100)}`;
        if (this.config.enableCache !== false) {
            const cached = this.cache.get(cacheKey);
            if (cached) return cached;
        }

        // 7. Inspectores Locales Heurísticos (incluyendo PaddingEvasion)
        const threats: ThreatIncident[] = [];
        for (const inspector of this.inspectors) {
            const incident = await inspector.inspect(context);
            if (incident) threats.push(incident);
        }

        // 8. Consulta Agente Urano Remoto con Circuit Breaker
        if (this.config.agentWebhookUrl && threats.length === 0) {
            const canCall = this.circuitBreaker ? this.circuitBreaker.canCallRemote() : true;

            if (canCall) {
                const remoteDecision = await this.queryRemoteAgent(context);
                if (remoteDecision) {
                    if (this.config.enableCache !== false) {
                        this.cache.set(cacheKey, remoteDecision);
                    }
                    return remoteDecision;
                }
            } else {
                console.warn(`[UranoGuard] Circuit Breaker ABIERTO — usando solo inspección local para ${context.path}`);
            }
        }

        // 9. Consolidar Veredicto Final
        const maxScore = threats.length > 0 ? Math.max(...threats.map(t => t.riskScore)) : 0;
        const securityMode = this.config.securityMode || 'block_threats';
        let action: 'ALLOW' | 'BLOCK' | 'REDIRECT' | 'QUARANTINE' | 'MONITOR' = 'ALLOW';
        let allowed = true;

        if (maxScore >= 60) {
            if (securityMode === 'block_threats' || securityMode === 'strict_zero_trust') {
                action = 'BLOCK'; allowed = false;
            } else if (securityMode === 'monitor_only') {
                action = 'MONITOR'; allowed = true;
            } else if (securityMode === 'quarantine') {
                action = 'QUARANTINE'; allowed = false;
            }
        } else if (maxScore >= 30 && securityMode === 'strict_zero_trust') {
            action = 'BLOCK'; allowed = false;
        }

        const sanitizedBody = allowed && this.config.inspectors?.piiDataMasking !== false
            ? this.piiMasker.sanitize(context.body)
            : context.body;

        const decision: SecurityDecision = {
            allowed, action, riskScore: maxScore, threats,
            reason: threats.length > 0 ? threats[0].summary : undefined,
            sanitizedBody,
            latencyMs: Date.now() - start,
            source: 'LOCAL_INSPECTOR'
        };

        if (this.config.enableCache !== false) {
            this.cache.set(cacheKey, decision);
        }

        return decision;
    }

    private async queryRemoteAgent(context: GuardRequestContext): Promise<SecurityDecision | null> {
        const start = Date.now();
        const timeoutMs = this.config.timeoutMs || 1500;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const headers: Record<string, string> = { 'Content-Type': 'application/json' };
            if (this.config.apiKey) headers['Authorization'] = `Bearer ${this.config.apiKey}`;

            const res = await fetch(this.config.agentWebhookUrl!, {
                method: 'POST', headers,
                body: JSON.stringify({ sender: context.senderId || context.ip, content: context.body, path: context.path, method: context.method }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            const latencyMs = Date.now() - start;
            this.circuitBreaker?.recordSuccess(latencyMs);

            if (!res.ok) { this.circuitBreaker?.recordFailure(); return null; }

            const data = await res.json() as any;
            const isThreat = data.verdict === 'CRITICAL_THREAT' || data.riskScore >= 60;

            return {
                allowed: !isThreat,
                action: isThreat ? 'BLOCK' : 'ALLOW',
                riskScore: data.riskScore || (isThreat ? 80 : 0),
                threats: isThreat ? [{
                    id: `thr_rem_${Date.now()}`,
                    category: 'REMOTE_AGENT_VERDICT',
                    severity: 'HIGH',
                    riskScore: data.riskScore || 80,
                    summary: data.reason || 'Bloqueado por el Agente de Ciberdefensa Urano',
                    detectedAt: new Date().toISOString(),
                    sender: context.senderId || context.ip
                }] : [],
                latencyMs,
                source: 'REMOTE_AGENT'
            };
        } catch (err: any) {
            clearTimeout(timeoutId);
            this.circuitBreaker?.recordFailure();
            return null;
        }
    }

    private allow(start: number, source: SecurityDecision['source']): SecurityDecision {
        return { allowed: true, action: 'ALLOW', riskScore: 0, threats: [], latencyMs: Date.now() - start, source };
    }

    private block(
        start: number,
        riskScore: number,
        threats: ThreatIncident[],
        reason: string | undefined,
        source: SecurityDecision['source']
    ): SecurityDecision {
        return { allowed: false, action: 'BLOCK', riskScore, threats, reason, latencyMs: Date.now() - start, source };
    }
}
