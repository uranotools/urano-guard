import { GuardRequestContext, SecurityDecision } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { InspectorFlags, SecurityMode, UranoGuardConfig } from '../types/config';
import { GuardLogger, MetricsExporter, createSilentLogger } from '../types/logger';
import { ThreatRegistry } from './ThreatRegistry';
import { CacheManager } from './CacheManager';
import { CircuitBreaker } from './CircuitBreaker';
import { ReplayGuard } from './ReplayGuard';
import { SemanticRateLimiter } from './SemanticRateLimiter';
import { RequestFingerprinter } from './RequestFingerprinter';
import { InspectorBase, flattenIncidents } from '../inspectors/InspectorBase';
import { PiiDataMasker } from '../inspectors/PiiDataMasker';
import { LocalAnalysis, RemoteAgentClient, resolveRemoteAgentConfig, shouldInvokeRemoteWithRange } from './RemoteAgentClient';
import { resolveRoutePolicy } from './routePolicy';
import { sha256Hex } from '../utils/crypto';
import { stringifySafe } from '../utils/inspectText';
import { SharedStore } from '../types/store';
import { EventBus } from './EventBus';

const INSPECTOR_FLAGS: Record<string, keyof InspectorFlags> = {
    PromptInjectionInspector: 'promptInjection',
    MaliciousUrlInspector: 'maliciousUrls',
    SqlInjectionInspector: 'sqlInjection',
    CommandInjectionInspector: 'commandInjection',
    XssInspector: 'xss',
    InjectionSqlCmdInspector: 'sqlAndCommands',
    BotFuzzingInspector: 'botFuzzing',
    PaddingEvasionInspector: 'paddingEvasion',
    JwtTamperingInspector: 'jwtTampering',
    GraphqlAbuseInspector: 'graphqlAbuse'
};

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
    private remoteClient?: RemoteAgentClient;
    private logger: GuardLogger;
    private metrics?: MetricsExporter;

    constructor(
        config: UranoGuardConfig,
        registry: ThreatRegistry,
        cache: CacheManager,
        inspectors: InspectorBase[],
        extras?: {
            logger?: GuardLogger;
            metrics?: MetricsExporter;
            circuitBreaker?: CircuitBreaker;
            store?: SharedStore;
            eventBus?: EventBus;
        }
    ) {
        this.config = config;
        this.registry = registry;
        this.cache = cache;
        this.inspectors = inspectors;
        this.logger = extras?.logger ?? config.logger ?? createSilentLogger();
        this.metrics = extras?.metrics ?? config.metrics;
        this.piiMasker = new PiiDataMasker(config.inspectors?.piiDataMasking !== false);

        if (config.circuitBreaker?.enabled !== false) {
            this.circuitBreaker = extras?.circuitBreaker ?? new CircuitBreaker({
                latencyThresholdMs: config.circuitBreaker?.latencyThresholdMs,
                failureThreshold: config.circuitBreaker?.failureThreshold,
                recoveryTimeMs: config.circuitBreaker?.recoveryTimeMs,
                probeSuccessThreshold: config.circuitBreaker?.probeSuccessThreshold,
                logger: this.logger,
                metrics: this.metrics,
                store: extras?.store ?? config.store
            });
        }

        if (config.replayGuard?.enabled) {
            this.replayGuard = new ReplayGuard({
                timestampWindowMs: config.replayGuard?.timestampWindowMs,
                logger: this.logger,
                store: extras?.store ?? config.store
            });
        }

        if (config.semanticRateLimit?.enabled) {
            this.rateLimiter = new SemanticRateLimiter({
                windowMs: config.semanticRateLimit?.windowMs,
                maxRequestsPerWindow: config.semanticRateLimit?.maxRequestsPerWindow,
                campaignIpThreshold: config.semanticRateLimit?.campaignIpThreshold,
                store: extras?.store ?? config.store
            });
        }

        if (config.fingerprinting?.enabled) {
            this.fingerprinter = new RequestFingerprinter(10_000, extras?.store ?? config.store);
        }

        const remoteCfg = resolveRemoteAgentConfig(config);
        if (remoteCfg) {
            const store = extras?.store ?? config.store;
            this.remoteClient = new RemoteAgentClient({
                config: remoteCfg,
                circuitBreaker: this.circuitBreaker,
                logger: this.logger,
                metrics: this.metrics,
                securityMode: config.securityMode,
                useLegacyPayload: !config.remoteAgent?.payload && !config.remoteAgent?.buildPayload && !!config.agentWebhookUrl,
                store,
                onInvestigateComplete: (event) => extras?.eventBus?.emit('agentInvestigationComplete', event)
            });
        }
    }

    addInspector(inspector: InspectorBase): void {
        this.inspectors.push(inspector);
    }

    async evaluate(context: GuardRequestContext): Promise<SecurityDecision> {
        const start = Date.now();
        const senderId = context.senderId || context.ip;
        const route = resolveRoutePolicy(this.config.routePolicies, context.method, context.path);
        if (route?.skip) {
            return this.allow(start, 'LOCAL_INSPECTOR');
        }
        const securityMode: SecurityMode = route?.securityMode || this.config.securityMode || 'block_threats';

        if (await this.registry.isWhitelisted(senderId)) {
            return this.allow(start, 'LOCAL_INSPECTOR');
        }

        if (await this.registry.isBlacklisted(senderId)) {
            return this.block(start, 100, [{
                id: newIncidentId('thr_blk'),
                category: 'BLACKLISTED',
                severity: 'CRITICAL',
                riskScore: 100,
                summary: `Sender ${senderId} is blacklisted.`,
                detectedAt: new Date().toISOString(),
                sender: senderId
            }], 'Sender is blacklisted', 'LOCAL_INSPECTOR');
        }

        if (this.replayGuard) {
            const replayCheck = await this.replayGuard.check(context.headers as any);
            if (!replayCheck.valid) {
                const isStrict = this.config.replayGuard?.strict === true;
                const incident: ThreatIncident = {
                    id: newIncidentId('thr_replay'),
                    category: 'CUSTOM',
                    severity: isStrict ? 'HIGH' : 'MEDIUM',
                    riskScore: isStrict ? 80 : 40,
                    summary: `Anti-replay triggered: ${replayCheck.reason}`,
                    detectedAt: new Date().toISOString(),
                    sender: senderId
                };
                if (isStrict) {
                    return this.block(start, 80, [incident], replayCheck.reason, 'LOCAL_INSPECTOR');
                }
                this.logger.warn(`ReplayGuard ${replayCheck.reason} from ${senderId}`);
            }
        }

        if (this.fingerprinter) {
            const maxBytes = this.config.maxBodyBytes ?? 256 * 1024;
            const bodySnippet = stringifySafe(context.body, maxBytes);
            const fp = await this.fingerprinter.fingerprint(context.headers as any, context.method, context.path, bodySnippet);
            const threshold = this.config.fingerprinting?.suspiciousThreshold ?? 10;
            if (fp.seenBefore && fp.occurrences >= threshold) {
                return this.block(start, 75, [{
                    id: newIncidentId('thr_fp'),
                    category: 'BOT_FUZZING',
                    severity: 'HIGH',
                    riskScore: 75,
                    summary: `Persistent attacker fingerprint ${fp.fingerprint} (${fp.occurrences} hits).`,
                    detectedAt: new Date().toISOString(),
                    sender: senderId,
                    details: { fingerprint: fp.fingerprint, occurrences: fp.occurrences }
                }], 'Repetitive behavioral pattern', 'LOCAL_INSPECTOR');
            }
        }

        if (this.rateLimiter) {
            const maxBytes = this.config.maxBodyBytes ?? 256 * 1024;
            const bodyStr = stringifySafe(context.body, maxBytes);
            const semanticKey = this.rateLimiter.buildSemanticKey(context.method, context.path, bodyStr);
            const rateResult = await this.rateLimiter.check(semanticKey, context.ip);

            if (rateResult === 'CAMPAIGN_DETECTED') {
                return this.block(start, 85, [{
                    id: newIncidentId('thr_campaign'),
                    category: 'BOT_FUZZING',
                    severity: 'CRITICAL',
                    riskScore: 85,
                    summary: `Distributed reconnaissance campaign on ${semanticKey}`,
                    detectedAt: new Date().toISOString(),
                    sender: senderId
                }], 'Coordinated campaign detected', 'LOCAL_INSPECTOR');
            }

            if (rateResult === 'RATE_LIMITED') {
                return this.block(start, 60, [{
                    id: newIncidentId('thr_rl'),
                    category: 'BOT_FUZZING',
                    severity: 'HIGH',
                    riskScore: 60,
                    summary: `Semantic rate limit exceeded for ${semanticKey}`,
                    detectedAt: new Date().toISOString(),
                    sender: senderId
                }], 'Semantic rate limit exceeded', 'LOCAL_INSPECTOR');
            }
        }

        const cacheKey = this.buildCacheKey(senderId, context);
        if (this.config.enableCache !== false) {
            const cached = await this.cache.get(cacheKey);
            if (cached) return cached;
        }

        const threats: ThreatIncident[] = [];
        for (const inspector of this.inspectors) {
            if (!this.isInspectorActive(inspector, route?.inspectors)) continue;
            const incident = await inspector.inspect(context);
            const found = flattenIncidents(incident);
            threats.push(...found);
            if (found.length) {
                this.metrics?.increment('inspectorHits', found.length, { inspector: inspector.name });
            }
        }

        const local: LocalAnalysis = {
            threats,
            maxRiskScore: threats.length ? Math.max(...threats.map(t => t.riskScore)) : 0
        };

        let remoteDecision: SecurityDecision | null = null;
        const remoteCfg = this.config.remoteAgent;
        if (this.remoteClient && shouldInvokeRemoteWithRange(
            remoteCfg?.invokeWhen,
            local,
            remoteCfg?.minLocalScoreToInvoke ?? 30,
            remoteCfg?.maxLocalScoreToInvoke ?? 59
        )) {
            remoteDecision = await this.remoteClient.query(context, local);
        }

        const decision = this.consolidate(start, local, securityMode, context, remoteDecision);

        if (decision.action === 'QUARANTINE' && !decision.allowed) {
            await this.registry.block(senderId, this.config.quarantineTtlMs ?? 15 * 60_000);
        }

        if (this.config.enableCache !== false) {
            await this.cache.set(cacheKey, decision);
        }
        return decision;
    }

    private consolidate(
        start: number,
        local: LocalAnalysis,
        securityMode: SecurityMode,
        context: GuardRequestContext,
        remote: SecurityDecision | null
    ): SecurityDecision {
        const threats = [...local.threats];
        if (remote?.threats?.length) threats.push(...remote.threats);

        let maxScore = threats.length ? Math.max(...threats.map(t => t.riskScore)) : 0;
        if (remote && remote.riskScore > maxScore) maxScore = remote.riskScore;

        const localBlocked = this.scoreBlocks(local.maxRiskScore, securityMode);
        const remoteBlocks = remote ? remote.allowed === false : false;

        let allowed = true;
        let action: SecurityDecision['action'] = 'ALLOW';

        if (localBlocked || remoteBlocks) {
            const mapped = this.actionForMode(securityMode, maxScore);
            allowed = mapped.allowed;
            action = mapped.action;
            if (securityMode !== 'monitor_only' && localBlocked && remote?.allowed) {
                allowed = false;
                action = mapped.action === 'ALLOW' ? 'BLOCK' : mapped.action;
            }
        } else if (remote && !remote.allowed) {
            allowed = false;
            action = remote.action;
        }

        if (action === 'REDIRECT' && this.config.onRedirect) {
            // adapters resolve the URL
        }

        const sanitizedBody = allowed && this.config.inspectors?.piiDataMasking !== false
            ? this.piiMasker.sanitize(context.body)
            : context.body;

        return {
            allowed,
            action,
            riskScore: maxScore,
            threats,
            reason: threats[0]?.summary || remote?.reason,
            redirectUrl: remote?.redirectUrl,
            sanitizedBody,
            latencyMs: Date.now() - start,
            source: remote ? 'REMOTE_AGENT' : 'LOCAL_INSPECTOR',
            agentAnalysis: remote?.agentAnalysis,
            agentReport: remote?.agentReport,
            investigationPending: remote?.investigationPending
        };
    }

    private scoreBlocks(score: number, mode: SecurityMode): boolean {
        if (score >= 60) return true;
        if (score >= 30 && mode === 'strict_zero_trust') return true;
        return false;
    }

    private actionForMode(mode: SecurityMode, score: number): { allowed: boolean; action: SecurityDecision['action'] } {
        const fallback = this.config.defaultAction;
        if (mode === 'monitor_only') return { allowed: true, action: 'MONITOR' };
        if (mode === 'quarantine' || fallback === 'quarantine') return { allowed: false, action: 'QUARANTINE' };
        if (fallback === 'allow') return { allowed: true, action: 'ALLOW' };
        if (fallback === 'monitor') return { allowed: true, action: 'MONITOR' };
        if (score >= 60 || mode === 'strict_zero_trust' || mode === 'block_threats') {
            return { allowed: false, action: 'BLOCK' };
        }
        return { allowed: true, action: 'ALLOW' };
    }

    private isInspectorActive(inspector: InspectorBase, routeFlags?: InspectorFlags): boolean {
        if (!inspector.enabled) return false;
        const flag = INSPECTOR_FLAGS[inspector.name];
        if (!flag || !routeFlags) return true;
        const override = routeFlags[flag];
        if (override === undefined) return true;
        return override !== false;
    }

    private buildCacheKey(senderId: string, context: GuardRequestContext): string {
        const maxBytes = this.config.maxBodyBytes ?? 256 * 1024;
        const body = stringifySafe(context.body, maxBytes);
        return sha256Hex(`${senderId}|${context.method}|${context.path}|${body}`);
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
