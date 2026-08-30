import { MetricsExporter } from '../types/logger';
import {
    OtelAttributes,
    OtelCounter,
    OtelHistogram,
    OtelMeter,
    OtelMetricOptions,
    OtelSynchronousGauge,
    OpenTelemetryMetricsOptions
} from '../types/otel';

const LATENCY_BUCKETS_MS = [10, 50, 100, 250, 500, 1000, 2500, 5000];

const NAME_MAP: Record<string, string> = {
    requestBlocked: 'urano_guard_request_blocked_total',
    requestAllowed: 'urano_guard_request_allowed_total',
    threatDetected: 'urano_guard_threat_detected_total',
    inspectorHits: 'urano_guard_inspector_hits_total',
    remoteAgentLatency: 'urano_guard_remote_agent_latency_ms',
    remoteAgentSuccess: 'urano_guard_remote_agent_success_total',
    remoteAgentFailure: 'urano_guard_remote_agent_failure_total',
    remoteAgentSkipped: 'urano_guard_remote_agent_skipped_total',
    circuitState: 'urano_guard_circuit_state'
};

const COUNTER_LOGICAL = [
    'requestBlocked',
    'requestAllowed',
    'threatDetected',
    'inspectorHits',
    'remoteAgentSuccess',
    'remoteAgentFailure',
    'remoteAgentSkipped'
] as const;

const DESCRIPTIONS: Record<string, string> = {
    urano_guard_request_blocked_total: 'Requests blocked by Urano Guard',
    urano_guard_request_allowed_total: 'Requests allowed by Urano Guard',
    urano_guard_threat_detected_total: 'Threat incidents detected by Urano Guard',
    urano_guard_inspector_hits_total: 'Inspector hit count',
    urano_guard_remote_agent_latency_ms: 'Remote agent round-trip latency',
    urano_guard_remote_agent_success_total: 'Remote agent successes',
    urano_guard_remote_agent_failure_total: 'Remote agent failures',
    urano_guard_remote_agent_skipped_total: 'Remote agent invocations skipped',
    urano_guard_circuit_state: 'Remote agent circuit state (0=CLOSED, 1=HALF_OPEN, 2=OPEN)'
};

function sanitizeName(name: string): string {
    if (NAME_MAP[name]) return NAME_MAP[name];
    const cleaned = name.replace(/[^a-zA-Z0-9_]/g, '_');
    return cleaned.startsWith('urano_guard_') ? cleaned : `urano_guard_${cleaned}`;
}

function labelKey(labels?: Record<string, string>): string {
    if (!labels) return '';
    return Object.keys(labels).sort().map(k => `${k}=${labels[k]}`).join(',');
}

function instrumentOptions(metric: string, extra?: OtelMetricOptions): OtelMetricOptions {
    const opts: OtelMetricOptions = {
        description: DESCRIPTIONS[metric] || metric.replace(/_/g, ' ')
    };
    if (metric === 'urano_guard_remote_agent_latency_ms') {
        opts.unit = 'ms';
        opts.advice = { explicitBucketBoundaries: LATENCY_BUCKETS_MS };
    }
    return extra ? { ...opts, ...extra } : opts;
}

interface GaugeSeries {
    value: number;
    attributes: OtelAttributes;
}

/**
 * MetricsExporter that forwards to an injected OpenTelemetry Meter.
 * Zero runtime dependencies — the Meter is duck-typed.
 */
export class OpenTelemetryMetrics implements MetricsExporter {
    private readonly meter: OtelMeter;
    private readonly counters = new Map<string, OtelCounter>();
    private readonly histograms = new Map<string, OtelHistogram>();
    private readonly syncGauges = new Map<string, OtelSynchronousGauge>();
    private readonly lastGauges = new Map<string, GaugeSeries>();
    private readonly observableReady = new Set<string>();

    constructor(meter: OtelMeter) {
        this.meter = meter;
        for (const logical of COUNTER_LOGICAL) {
            this.ensureCounter(NAME_MAP[logical]);
        }
        this.ensureHistogram(NAME_MAP.remoteAgentLatency);
        this.ensureGaugeInstrument(NAME_MAP.circuitState);
    }

    increment(name: string, value = 1, tags?: Record<string, string>): void {
        this.ensureCounter(sanitizeName(name)).add(value, tags);
    }

    observe(name: string, value: number, tags?: Record<string, string>): void {
        const histogram = this.ensureHistogram(sanitizeName(name));
        histogram?.record(value, tags);
    }

    gauge(name: string, value: number, tags?: Record<string, string>): void {
        const metric = sanitizeName(name);
        const attributes = tags || {};
        const sync = this.ensureGaugeInstrument(metric);
        if (sync) {
            sync.record(value, attributes);
            return;
        }
        if (this.observableReady.has(metric)) {
            this.lastGauges.set(`${metric}|${labelKey(tags)}`, { value, attributes });
        }
    }

    private ensureCounter(metric: string): OtelCounter {
        let counter = this.counters.get(metric);
        if (!counter) {
            counter = this.meter.createCounter(metric, instrumentOptions(metric));
            this.counters.set(metric, counter);
        }
        return counter;
    }

    private ensureHistogram(metric: string): OtelHistogram | undefined {
        if (this.histograms.has(metric)) return this.histograms.get(metric);
        if (typeof this.meter.createHistogram !== 'function') return undefined;
        const histogram = this.meter.createHistogram(metric, instrumentOptions(metric));
        this.histograms.set(metric, histogram);
        return histogram;
    }

    private ensureGaugeInstrument(metric: string): OtelSynchronousGauge | undefined {
        if (this.syncGauges.has(metric)) return this.syncGauges.get(metric);
        if (typeof this.meter.createGauge === 'function') {
            const gauge = this.meter.createGauge(metric, instrumentOptions(metric));
            this.syncGauges.set(metric, gauge);
            return gauge;
        }
        if (!this.observableReady.has(metric) && typeof this.meter.createObservableGauge === 'function') {
            const observable = this.meter.createObservableGauge(metric, instrumentOptions(metric));
            observable.addCallback(result => {
                for (const [key, series] of this.lastGauges) {
                    if (key.startsWith(`${metric}|`)) {
                        result.observe(series.value, series.attributes);
                    }
                }
            });
            this.observableReady.add(metric);
        }
        return undefined;
    }
}

export function createOpenTelemetryMetrics(options: OpenTelemetryMetricsOptions): OpenTelemetryMetrics {
    const meter = options?.meter;
    if (!meter || typeof meter.createCounter !== 'function') {
        throw new TypeError('createOpenTelemetryMetrics({ meter }) requires a Meter with createCounter()');
    }
    return new OpenTelemetryMetrics(meter);
}
