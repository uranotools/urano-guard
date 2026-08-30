import { describe, expect, it } from 'vitest';
import { createOpenTelemetryMetrics } from '../src/core/OpenTelemetryMetrics';
import { OtelAttributes, OtelMeter, OtelObservableResult } from '../src/types/otel';

interface AddCall {
    name: string;
    value: number;
    attrs?: OtelAttributes;
}

interface RecordCall {
    name: string;
    value: number;
    attrs?: OtelAttributes;
}

function createFakeMeter(opts?: { histogram?: boolean; gauge?: boolean; observable?: boolean }) {
    const adds: AddCall[] = [];
    const records: RecordCall[] = [];
    const gauges: RecordCall[] = [];
    const created = { counters: [] as string[], histograms: [] as string[], gauges: [] as string[], observables: [] as string[] };
    const observableCallbacks: Array<{ name: string; cb: (result: OtelObservableResult) => void }> = [];

    const meter: OtelMeter = {
        createCounter(name) {
            created.counters.push(name);
            return {
                add(value, attrs) {
                    adds.push({ name, value, attrs });
                }
            };
        }
    };

    if (opts?.histogram !== false) {
        meter.createHistogram = name => {
            created.histograms.push(name);
            return {
                record(value, attrs) {
                    records.push({ name, value, attrs });
                }
            };
        };
    }

    if (opts?.gauge !== false) {
        meter.createGauge = name => {
            created.gauges.push(name);
            return {
                record(value, attrs) {
                    gauges.push({ name, value, attrs });
                }
            };
        };
    }

    if (opts?.observable) {
        meter.createObservableGauge = name => {
            created.observables.push(name);
            return {
                addCallback(cb) {
                    observableCallbacks.push({ name, cb });
                }
            };
        };
    }

    return { meter, adds, records, gauges, created, observableCallbacks };
}

describe('createOpenTelemetryMetrics', () => {
    it('requires a Meter with createCounter', () => {
        expect(() => createOpenTelemetryMetrics({} as any)).toThrow(/createCounter/);
        expect(() => createOpenTelemetryMetrics({ meter: {} as any })).toThrow(/createCounter/);
    });

    it('maps logical counter names and records add() calls', () => {
        const { meter, adds } = createFakeMeter();
        const metrics = createOpenTelemetryMetrics({ meter });

        metrics.increment('requestBlocked');
        metrics.increment('requestAllowed', 1);
        metrics.increment('threatDetected', 2);
        metrics.increment('inspectorHits', 3, { inspector: 'xss' });
        metrics.increment('remoteAgentSuccess');
        metrics.increment('remoteAgentFailure', 1, { reason: 'http' });

        expect(adds).toEqual([
            { name: 'urano_guard_request_blocked_total', value: 1, attrs: undefined },
            { name: 'urano_guard_request_allowed_total', value: 1, attrs: undefined },
            { name: 'urano_guard_threat_detected_total', value: 2, attrs: undefined },
            { name: 'urano_guard_inspector_hits_total', value: 3, attrs: { inspector: 'xss' } },
            { name: 'urano_guard_remote_agent_success_total', value: 1, attrs: undefined },
            { name: 'urano_guard_remote_agent_failure_total', value: 1, attrs: { reason: 'http' } }
        ]);
    });

    it('pre-creates the known Prometheus-aligned instruments', () => {
        const { meter, created } = createFakeMeter();
        createOpenTelemetryMetrics({ meter });

        expect(created.counters).toEqual([
            'urano_guard_request_blocked_total',
            'urano_guard_request_allowed_total',
            'urano_guard_threat_detected_total',
            'urano_guard_inspector_hits_total',
            'urano_guard_remote_agent_success_total',
            'urano_guard_remote_agent_failure_total',
            'urano_guard_remote_agent_skipped_total'
        ]);
        expect(created.histograms).toEqual(['urano_guard_remote_agent_latency_ms']);
        expect(created.gauges).toEqual(['urano_guard_circuit_state']);
    });

    it('observes remote agent latency on a histogram', () => {
        const { meter, records } = createFakeMeter();
        const metrics = createOpenTelemetryMetrics({ meter });
        metrics.observe!('remoteAgentLatency', 42, { path: '/api' });
        expect(records).toEqual([
            { name: 'urano_guard_remote_agent_latency_ms', value: 42, attrs: { path: '/api' } }
        ]);
    });

    it('records the circuit gauge when createGauge is present', () => {
        const { meter, gauges } = createFakeMeter();
        const metrics = createOpenTelemetryMetrics({ meter });
        metrics.gauge!('circuitState', 2, { state: 'OPEN' });
        expect(gauges).toEqual([
            { name: 'urano_guard_circuit_state', value: 2, attrs: { state: 'OPEN' } }
        ]);
    });

    it('uses createObservableGauge when createGauge is missing', () => {
        const { meter, created, observableCallbacks } = createFakeMeter({
            gauge: false,
            observable: true
        });
        const metrics = createOpenTelemetryMetrics({ meter });
        expect(created.observables).toEqual(['urano_guard_circuit_state']);

        metrics.gauge!('circuitState', 1, { state: 'HALF_OPEN' });
        const observed: RecordCall[] = [];
        observableCallbacks[0].cb({
            observe(value, attrs) {
                observed.push({ name: 'urano_guard_circuit_state', value, attrs });
            }
        });
        expect(observed).toEqual([
            { name: 'urano_guard_circuit_state', value: 1, attrs: { state: 'HALF_OPEN' } }
        ]);
    });

    it('skips observe/gauge when the Meter lacks those APIs', () => {
        const { meter } = createFakeMeter({ histogram: false, gauge: false });
        const metrics = createOpenTelemetryMetrics({ meter });
        expect(() => metrics.observe!('remoteAgentLatency', 10)).not.toThrow();
        expect(() => metrics.gauge!('circuitState', 0, { state: 'CLOSED' })).not.toThrow();
    });

    it('prefixes unknown metric names like Prometheus', () => {
        const { meter, adds } = createFakeMeter();
        const metrics = createOpenTelemetryMetrics({ meter });
        metrics.increment('custom.event', 1, { source: 'app' });
        metrics.increment('urano_guard_already_prefixed', 4);
        expect(adds.slice(-2)).toEqual([
            { name: 'urano_guard_custom_event', value: 1, attrs: { source: 'app' } },
            { name: 'urano_guard_already_prefixed', value: 4, attrs: undefined }
        ]);
    });
});
