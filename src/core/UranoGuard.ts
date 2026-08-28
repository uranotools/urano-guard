import { UranoGuardConfig } from '../types/config';
import { GuardRequestContext, SecurityDecision } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { EventBus } from './EventBus';
import { CacheManager } from './CacheManager';
import { ThreatRegistry } from './ThreatRegistry';
import { Evaluator } from './Evaluator';
import { HoneypotRouter } from './HoneypotRouter';
import { InspectorBase } from '../inspectors/InspectorBase';
import { PromptInjectionInspector } from '../inspectors/PromptInjectionInspector';
import { MaliciousUrlInspector } from '../inspectors/MaliciousUrlInspector';
import { InjectionSqlCmdInspector } from '../inspectors/InjectionSqlCmdInspector';
import { BotFuzzingInspector } from '../inspectors/BotFuzzingInspector';
import { PaddingEvasionInspector } from '../inspectors/PaddingEvasionInspector';
import { ExpressAdapter } from '../adapters/ExpressAdapter';
import { FastifyAdapter } from '../adapters/FastifyAdapter';
import { EdgeAdapter } from '../adapters/EdgeAdapter';
import { HttpAdapter } from '../adapters/HttpAdapter';

export class UranoGuard {
    readonly config: UranoGuardConfig;
    readonly eventBus: EventBus;
    readonly registry: ThreatRegistry;
    readonly cache: CacheManager;
    readonly evaluator: Evaluator;
    readonly honeypot?: HoneypotRouter;
    private customInspectors: InspectorBase[] = [];

    constructor(config: UranoGuardConfig = {}) {
        this.config = config;
        this.eventBus = new EventBus();
        this.registry = new ThreatRegistry(
            config.blockedIdentifiers || [],
            config.whitelistedIdentifiers || []
        );
        this.cache = new CacheManager(config.cacheTtlMs || 60_000);

        const defaultInspectors: InspectorBase[] = [
            new PromptInjectionInspector(config.inspectors?.promptInjection !== false),
            new MaliciousUrlInspector(config.inspectors?.maliciousUrls !== false),
            new InjectionSqlCmdInspector(config.inspectors?.sqlAndCommands !== false),
            new BotFuzzingInspector(config.inspectors?.botFuzzing !== false),
            new PaddingEvasionInspector(config.inspectors?.paddingEvasion !== false)
        ];

        this.evaluator = new Evaluator(this.config, this.registry, this.cache, defaultInspectors);

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
    }

    async inspect(context: GuardRequestContext): Promise<SecurityDecision> {
        // Detectar si el atacante regresó con un honey-token activo
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
        this.customInspectors.push(inspector);
    }

    block(identifier: string): void { this.registry.block(identifier); }
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
}

export function createUranoGuard(config: UranoGuardConfig = {}): UranoGuard {
    return new UranoGuard(config);
}
