import { UranoGuardConfig } from '../types/config';
import { GuardRequestContext, SecurityDecision } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { GuardLogger, resolveLogger } from '../types/logger';
import { EventBus } from './EventBus';
import { CacheManager } from './CacheManager';
import { ThreatRegistry } from './ThreatRegistry';
import { Evaluator } from './Evaluator';
import { HoneypotRouter } from './HoneypotRouter';
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
    private readonly logger: GuardLogger;

    constructor(config: UranoGuardConfig = {}) {
        this.config = config;
        this.logger = resolveLogger(config.logger);
        this.eventBus = new EventBus(this.logger);
        this.registry = new ThreatRegistry(
            config.blockedIdentifiers || [],
            config.whitelistedIdentifiers || []
        );
        this.cache = new CacheManager(config.cacheTtlMs || 60_000);

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
            metrics: config.metrics
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

        if (config.metrics) {
            this.eventBus.on('requestBlocked', () => config.metrics!.increment('requestBlocked', 1));
            this.eventBus.on('requestAllowed', () => config.metrics!.increment('requestAllowed', 1));
            this.eventBus.on('threatDetected', () => config.metrics!.increment('threatDetected', 1));
        }
    }

    getLogger(): GuardLogger {
        return this.logger;
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

        return decision;
    }

    registerInspector(inspector: InspectorBase): void {
        this.evaluator.addInspector(inspector);
    }

    block(identifier: string, ttlMs?: number): void { this.registry.block(identifier, ttlMs); }
    unblock(identifier: string): void { this.registry.unblock(identifier); }

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
