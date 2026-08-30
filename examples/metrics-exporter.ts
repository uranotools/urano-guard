import { MetricsExporter } from '../src/types/logger';

/** Drop-in MetricsExporter you can point at Prometheus / OpenTelemetry. */
export function createConsoleMetrics(): MetricsExporter {
    return {
        increment(name, value = 1, tags) {
            console.info(`[metric] ${name} +${value}`, tags || {});
        },
        observe(name, value, tags) {
            console.info(`[metric] ${name}=${value}`, tags || {});
        },
        gauge(name, value, tags) {
            console.info(`[metric] ${name} gauge ${value}`, tags || {});
        }
    };
}
