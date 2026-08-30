import { GuardLogger, createSilentLogger } from '../types/logger';

type EventHandler<T = any> = (data: T) => void | Promise<void>;

export class EventBus {
    private handlers = new Map<string, Set<EventHandler>>();
    private logger: GuardLogger;

    constructor(logger?: GuardLogger) {
        this.logger = logger ?? createSilentLogger();
    }

    setLogger(logger: GuardLogger): void {
        this.logger = logger;
    }

    on<T = any>(event: string, handler: EventHandler<T>): () => void {
        if (!this.handlers.has(event)) {
            this.handlers.set(event, new Set());
        }
        this.handlers.get(event)!.add(handler);
        return () => this.off(event, handler);
    }

    off(event: string, handler: EventHandler): void {
        this.handlers.get(event)?.delete(handler);
    }

    async emit<T = any>(event: string, data: T): Promise<void> {
        const listeners = this.handlers.get(event);
        if (!listeners) return;
        for (const handler of Array.from(listeners)) {
            try {
                await handler(data);
            } catch (err: any) {
                this.logger.error(`EventBus listener error for '${event}'`, err);
            }
        }
    }
}
