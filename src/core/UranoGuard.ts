import { UranoGuardConfig } from '../types/config';
import { GuardRequestContext, SecurityDecision } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { GuardLogger, MetricsExporter, resolveLogger } from '../types/logger';
import { AuditLogger, resolveAuditLogger, toAuditEvent } from '../types/audit';
import { EventBus } from './EventBus';
import { CacheManager } from './CacheManager';
import { ThreatRegistry } from './ThreatRegistry';
import { Evaluator } from './Evaluator';
import { HoneypotRouter } from './HoneypotRouter';
import { validateConfig } from './validateConfig';
import { MemoryStore, SharedStore } from './SharedStore';
import { createPrometheusMetrics, isPrometheusMetrics } from './PrometheusMetrics';
import { InspectorBase } from '../inspectors/InspectorBase';
import { PromptInjectionInspector } from '../inspectors/PromptInjectionInspector';
import { MaliciousUrlInspector } from '../inspectors/MaliciousUrlInspector';
import { SqlInjectionInspector } from '../inspectors/SqlInjectionInspector';
import { CommandInjectionInspector } from '../inspectors/CommandInjectionInspector';
import { XssInspector } from '../inspectors/XssInspector';
import { BotFuzzingInspector } from '../inspectors/BotFuzzingInspector';
import { PaddingEvasionInspector } from '../inspectors/PaddingEvasionInspector';
import { JwtTamperingInspector } from '../inspectors/JwtTamperingInspector';
import { GraphqlAbuseInspector } from '../inspectors/GraphqlAbuseInspector';
import { ExpressAdapter } from '../adapters/ExpressAdapter';
import { FastifyAdapter } from '../adapters/FastifyAdapter';
import { EdgeAdapter } from '../adapters/EdgeAdapter';
import { HttpAdapter } from '../adapters/HttpAdapter';
import { HonoAdapter } from '../adapters/HonoAdapter';

export class UranoGuard {
    readonly config: UranoGuardConfig;
    readonly eventBus: EventBus;
    readonly registry: ThreatRegistry;
    readonly cache: CacheManager;
    readonly evaluator: Evaluator;
    readonly honeypot?: HoneypotRouter;
    readonly store: SharedStore;
    private readonly logger: GuardLogger;
    private readonly auditLogger?: AuditLogger;
    private readonly metrics?: MetricsExporter;

    constructor(config: UranoGuardConfig = {}) {
        validateConfig(config);
        this.config = config;
        this.logger = resolveLogger(config.logger);
        this.auditLogger = resolveAuditLogger(config.auditLogger);
        this.metrics = config.metrics ?? createPrometheusMetrics();
        this.store = config.store ?? new MemoryStore({
            maxEntries: 10_000,
            defaultTtlMs: config.cacheTtlMs || 60_000
        });
        this.eventBus = new EventBus(this.logger);
        this.registry = new ThreatRegistry(
            config.blockedIdentifiers || [],
            config.whitelistedIdentifiers || [],
            this.store
        );
        this.cache = new CacheManager(config.cacheTtlMs || 60_000, 5000, this.store);

        const sqlOn = config.inspectors?.sqlAndCommands !== false && config.inspectors?.sqlInjection !== false;
        const cmdOn = config.inspectors?.sqlAndCommands !== false && config.inspectors?.commandInjection !== false;
        const xssOn = config.inspectors?.sqlAndCommands !== false && config.inspectors?.xss !== false;

        const defaultInspectors: InspectorBase[] = [
            new PromptInjectionInspector(config.inspectors?.promptInjection !== false),
            new MaliciousUrlInspector(
                config.inspectors?.maliciousUrls !== false,
                config.inspectors?.maliciousUrlsAllowHosts || []
            ),
            new SqlInjectionInspector(sqlOn),
            new CommandInjectionInspector(cmdOn),
            new XssInspector(xssOn),
            new BotFuzzingInspector(config.inspectors?.botFuzzing !== false),
            new PaddingEvasionInspector(config.inspectors?.paddingEvasion !== false),
            new JwtTamperingInspector(config.inspectors?.jwtTampering !== false),
            new GraphqlAbuseInspector(config.inspectors?.graphqlAbuse !== false)
        ];

        this.evaluator = new Evaluator(this.config, this.registry, this.cache, defaultInspectors, {
            logger: this.logger,
            metrics: this.metrics,
            store: this.store,
            eventBus: this.eventBus
        });

        if (config.honeypot?.tarpitEnabled || config.honeypot?.honeyTokensEnabled) {
            this.honeypot = new HoneypotRouter({
                tarpitEnabled: config.honeypot?.tarpitEnabled,
                tarpitDelayMs: config.honeypot?.tarpitDelayMs,
                honeyTokensEnabled: config.honeypot?.honeyTokensEnabled,
                onHoneyTokenAccessed: config.honeypot?.onHoneyTokenAccessed
            });
        }

        if (this.config.onThreatDetected) {
            this.eventBus.on('threatDetected', (data: { threat: ThreatIncident; req: GuardRequestContext }) => {
                this.config.onThreatDetected!(data.threat, data.req);
            });
        }

        if (this.metrics) {
            this.eventBus.on('requestBlocked', () => this.metrics!.increment('requestBlocked', 1));
            this.eventBus.on('requestAllowed', () => this.metrics!.increment('requestAllowed', 1));
            this.eventBus.on('threatDetected', () => this.metrics!.increment('threatDetected', 1));
        }
    }

    getLogger(): GuardLogger {
        return this.logger;
    }

    /**
     * Wait until ThreatRegistry constructor seeds (`ug:block:` / `ug:allow:`)
     * are written to the injected {@link SharedStore}.
     *
     * `inspect` already awaits this via `isWhitelisted` / `isBlacklisted`.
     * Call it before `listen()` when another process may read Redis first:
     *
     * ```ts
     * const guard = createUranoGuard({ store, blockedIdentifiers: ['1.2.3.4'] });
     * await guard.ready();
     * app.listen(3000);
     * ```
     *
     * Custom stores must implement the full SharedStore contract (`setNX`,
     * `sadd`, `smembers`, `decr`, `cas`) — not only get/set/incr/delete.
     */
    ready(): Promise<void> {
        return this.registry.ready();
    }

    async inspect(context: GuardRequestContext): Promise<SecurityDecision> {
        if (this.honeypot) {
            const honeyHit = this.honeypot.detectHoneyTokenAccess(context.body, context.headers as any);
            if (honeyHit) {
                await this.eventBus.emit('honeyTokenAccessed', { token: honeyHit, req: context });
            }
        }

        const decision = await this.evaluator.evaluate(context);

        if (!decision.allowed) {
            for (const threat of decision.threats) {
                await this.eventBus.emit('threatDetected', { threat, req: context });
            }
            await this.eventBus.emit('requestBlocked', { decision, req: context });
        } else {
            await this.eventBus.emit('requestAllowed', { decision, req: context });
        }

        if (this.auditLogger) {
            try {
                this.auditLogger(toAuditEvent(newIncidentId('req'), context.method, context.path, decision));
            } catch (err) {
                this.logger.warn('auditLogger failed', err);
            }
        }

        return decision;
    }

    prometheus(): string {
        if (isPrometheusMetrics(this.metrics)) {
            return this.metrics.renderPrometheus();
        }
        return '# Urano Guard: attach createPrometheusMetrics() via config.metrics to scrape\n';
    }

    metricsHandler(): (req: any, res: any) => void {
        return (_req: any, res: any) => {
            const body = this.prometheus();
            if (typeof res.status === 'function' && typeof res.send === 'function') {
                res.status(200);
                if (typeof res.type === 'function') res.type('text/plain');
                else if (typeof res.set === 'function') res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
                return res.send(body);
            }
            if (typeof res.writeHead === 'function') {
                res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
            }
            if (typeof res.end === 'function') res.end(body);
        };
    }

    registerInspector(inspector: InspectorBase): void {
        this.evaluator.addInspector(inspector);
    }

    block(identifier: string, ttlMs?: number): Promise<void> { return this.registry.block(identifier, ttlMs); }
    unblock(identifier: string): Promise<void> { return this.registry.unblock(identifier); }

    express(): (req: any, res: any, next: any) => void {
        return new ExpressAdapter(this).middleware();
    }

    fastify(): (request: any, reply: any) => Promise<void> {
        return new FastifyAdapter(this).hook();
    }

    edge(): (request: Request) => Promise<SecurityDecision> {
        return new EdgeAdapter(this).handler();
    }

    http(): (req: any, res: any, next?: () => void) => Promise<boolean> {
        return new HttpAdapter(this).handler();
    }

    hono() {
        return new HonoAdapter(this).middleware();
    }
}

export function createUranoGuard(config: UranoGuardConfig = {}): UranoGuard {
    return new UranoGuard(config);
}
