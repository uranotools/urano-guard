import { MetricsExporter } from '../src/types/logger';

/**
 * Debug MetricsExporter that prints to the console.
 * For a real scrape endpoint, use `createPrometheusMetrics()` from the package
 * and `guard.metricsHandler()` / `guard.prometheus()`. See prometheus-scrape.ts.
 */
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
