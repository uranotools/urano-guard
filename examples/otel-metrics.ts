/**
 * Bridge Urano Guard metrics to an OpenTelemetry Meter you already own.
 *
 * This package does **not** depend on `@opentelemetry/api` or `@opentelemetry/sdk-metrics`.
 * Create the Meter in your app and inject it:
 *
 *   // In your application (your dependencies, not this package):
 *   //   npm i @opentelemetry/api @opentelemetry/sdk-metrics
 *   import { metrics } from '@opentelemetry/api';
 *   import { MeterProvider, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
 *
 *   const provider = new MeterProvider({
 *       readers: [new PeriodicExportingMetricReader({ /* your OTLP/Prometheus exporter * / })]
 *   });
 *   metrics.setGlobalMeterProvider(provider);
 *   const meter = metrics.getMeter('urano-guard');
 *
 *   import { createUranoGuard, createOpenTelemetryMetrics } from '@uranotools/urano-guard';
 *   const guard = createUranoGuard({
 *       metrics: createOpenTelemetryMetrics({ meter })
 *   });
 *
 * Metric names match the Prometheus exporter (`urano_guard_request_blocked_total`, …).
 * Traces and spans are not exported.
 */

import { createUranoGuard, createOpenTelemetryMetrics } from '../src';

// Stand-in Meter so this file stays runnable without OTel packages.
const meter = {
    createCounter(name: string) {
        return {
            add(value: number, attrs?: Record<string, string>) {
                console.info(`[otel counter] ${name} +${value}`, attrs || {});
            }
        };
    },
    createHistogram(name: string) {
        return {
            record(value: number, attrs?: Record<string, string>) {
                console.info(`[otel histogram] ${name}=${value}`, attrs || {});
            }
        };
    },
    createGauge(name: string) {
        return {
            record(value: number, attrs?: Record<string, string>) {
                console.info(`[otel gauge] ${name}=${value}`, attrs || {});
            }
        };
    }
};

const metrics = createOpenTelemetryMetrics({ meter });
const guard = createUranoGuard({
    securityMode: 'monitor_only',
    metrics
});

void guard;
