export interface GuardLogger {
    debug?(message: string, meta?: unknown): void;
    info(message: string, meta?: unknown): void;
    warn(message: string, meta?: unknown): void;
    error(message: string, meta?: unknown): void;
}

export interface MetricsExporter {
    increment(name: string, value?: number, tags?: Record<string, string>): void;
    observe?(name: string, value: number, tags?: Record<string, string>): void;
    gauge?(name: string, value: number, tags?: Record<string, string>): void;
}

export function createSilentLogger(): GuardLogger {
    const noop = () => undefined;
    return { debug: noop, info: noop, warn: noop, error: noop };
}

export function resolveLogger(logger?: GuardLogger): GuardLogger {
    if (logger) return logger;
    return {
        debug: () => undefined,
        info: () => undefined,
        warn: () => undefined,
        error: (message, meta) => {
            if (typeof console !== 'undefined') {
                console.error(`[UranoGuard] ${message}`, meta ?? '');
            }
        }
    };
}
