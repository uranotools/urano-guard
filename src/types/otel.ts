/**
 * Duck-typed OpenTelemetry metrics surfaces.
 * Compatible with @opentelemetry/api Meter, but this package does not import it.
 */

export interface OtelMetricOptions {
    description?: string;
    unit?: string;
    advice?: { explicitBucketBoundaries?: number[] };
}

export type OtelAttributes = Record<string, string | number | boolean>;

export interface OtelCounter {
    add(value: number, attributes?: OtelAttributes): void;
}

export interface OtelHistogram {
    record(value: number, attributes?: OtelAttributes): void;
}

export interface OtelSynchronousGauge {
    record(value: number, attributes?: OtelAttributes): void;
}

export interface OtelObservableResult {
    observe(value: number, attributes?: OtelAttributes): void;
}

export interface OtelObservableGauge {
    addCallback(callback: (observableResult: OtelObservableResult) => void): void;
}

/** Minimal Meter: createCounter is required; histogram/gauge APIs are optional. */
export interface OtelMeter {
    createCounter(name: string, options?: OtelMetricOptions): OtelCounter;
    createHistogram?(name: string, options?: OtelMetricOptions): OtelHistogram;
    createGauge?(name: string, options?: OtelMetricOptions): OtelSynchronousGauge;
    createObservableGauge?(name: string, options?: OtelMetricOptions): OtelObservableGauge;
}

export interface OpenTelemetryMetricsOptions {
    meter: OtelMeter;
}
