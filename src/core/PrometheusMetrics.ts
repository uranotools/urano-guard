import { MetricsExporter } from '../types/logger';

const LATENCY_BUCKETS_MS = [10, 50, 100, 250, 500, 1000, 2500, 5000];

interface LabeledValue {
    name: string;
    labels: Record<string, string>;
    value: number;
}

interface HistogramSeries {
    name: string;
    labels: Record<string, string>;
    buckets: Map<number, number>;
    inf: number;
    sum: number;
    count: number;
}

function sanitizeName(name: string): string {
    const mapped: Record<string, string> = {
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
    if (mapped[name]) return mapped[name];
    const cleaned = name.replace(/[^a-zA-Z0-9_]/g, '_');
    return cleaned.startsWith('urano_guard_') ? cleaned : `urano_guard_${cleaned}`;
}

function escapeLabel(value: string): string {
    return value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

function labelKey(labels?: Record<string, string>): string {
    if (!labels) return '';
    return Object.keys(labels).sort().map(k => `${k}=${labels[k]}`).join(',');
}

function renderLabels(labels: Record<string, string>, extra?: Record<string, string>): string {
    const merged = { ...labels, ...extra };
    const keys = Object.keys(merged);
    if (!keys.length) return '';
    const inner = keys.sort().map(k => `${k}="${escapeLabel(merged[k])}"`).join(',');
    return `{${inner}}`;
}

/**
 * In-process Prometheus text exporter. Zero runtime dependencies.
 */
export class PrometheusMetrics implements MetricsExporter {
    private counters = new Map<string, LabeledValue>();
    private gauges = new Map<string, LabeledValue>();
    private histograms = new Map<string, HistogramSeries>();

    increment(name: string, value = 1, tags?: Record<string, string>): void {
        const metric = sanitizeName(name);
        const key = `${metric}|${labelKey(tags)}`;
        const existing = this.counters.get(key);
        if (existing) {
            existing.value += value;
            return;
        }
        this.counters.set(key, { name: metric, labels: { ...(tags || {}) }, value });
    }

    observe(name: string, value: number, tags?: Record<string, string>): void {
        const metric = sanitizeName(name);
        const key = `${metric}|${labelKey(tags)}`;
        let series = this.histograms.get(key);
        if (!series) {
            series = {
                name: metric,
                labels: { ...(tags || {}) },
                buckets: new Map(LATENCY_BUCKETS_MS.map(b => [b, 0])),
                inf: 0,
                sum: 0,
                count: 0
            };
            this.histograms.set(key, series);
        }
        series.sum += value;
        series.count += 1;
        series.inf += 1;
        for (const bound of LATENCY_BUCKETS_MS) {
            if (value <= bound) {
                series.buckets.set(bound, (series.buckets.get(bound) || 0) + 1);
            }
        }
    }

    gauge(name: string, value: number, tags?: Record<string, string>): void {
        const metric = sanitizeName(name);
        const key = `${metric}|${labelKey(tags)}`;
        this.gauges.set(key, { name: metric, labels: { ...(tags || {}) }, value });
    }

    renderPrometheus(): string {
        const lines: string[] = [];
        const seenHelp = new Set<string>();

        const ensureHeader = (name: string, type: string, help: string) => {
            if (seenHelp.has(name)) return;
            seenHelp.add(name);
            lines.push(`# HELP ${name} ${help}`);
            lines.push(`# TYPE ${name} ${type}`);
        };

        for (const item of this.counters.values()) {
            ensureHeader(item.name, 'counter', item.name.replace(/_/g, ' '));
            lines.push(`${item.name}${renderLabels(item.labels)} ${item.value}`);
        }

        for (const item of this.gauges.values()) {
            ensureHeader(item.name, 'gauge', item.name.replace(/_/g, ' '));
            lines.push(`${item.name}${renderLabels(item.labels)} ${item.value}`);
        }

        for (const series of this.histograms.values()) {
            ensureHeader(series.name, 'histogram', series.name.replace(/_/g, ' '));
            for (const bound of LATENCY_BUCKETS_MS) {
                lines.push(`${series.name}_bucket${renderLabels(series.labels, { le: String(bound) })} ${series.buckets.get(bound) || 0}`);
            }
            lines.push(`${series.name}_bucket${renderLabels(series.labels, { le: '+Inf' })} ${series.inf}`);
            lines.push(`${series.name}_sum${renderLabels(series.labels)} ${series.sum}`);
            lines.push(`${series.name}_count${renderLabels(series.labels)} ${series.count}`);
        }

        if (!lines.length) {
            return '# Urano Guard metrics (empty)\n';
        }
        return `${lines.join('\n')}\n`;
    }
}

export function createPrometheusMetrics(): PrometheusMetrics {
    return new PrometheusMetrics();
}

export function isPrometheusMetrics(metrics: MetricsExporter | undefined): metrics is PrometheusMetrics {
    return !!metrics && typeof (metrics as PrometheusMetrics).renderPrometheus === 'function';
}
