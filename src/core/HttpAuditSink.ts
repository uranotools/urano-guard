import { AuditEvent, AuditLogger } from '../types/audit';

export interface HttpAuditSinkOptions {
    url: string | undefined;
    headers?: Record<string, string>;
    timeoutMs?: number;
    onError?: (error: unknown) => void;
}

/**
 * Safe field pick — never serialize body, cookies, Authorization, or extras.
 */
function toSafePayload(event: AuditEvent): AuditEvent {
    return {
        requestId: event.requestId,
        action: event.action,
        allowed: event.allowed,
        riskScore: event.riskScore,
        threatCategories: event.threatCategories,
        path: event.path,
        method: event.method,
        source: event.source,
        latencyMs: event.latencyMs
    };
}

/**
 * POSTs AuditEvent JSON to a SIEM/webhook. Fire-and-forget with timeout.
 * Failures are swallowed so audit never breaks the request path.
 */
export function createHttpAuditSink(options: HttpAuditSinkOptions): AuditLogger {
    const url = options?.url;
    if (!url || typeof url !== 'string') {
        throw new TypeError('createHttpAuditSink({ url }) requires a webhook URL');
    }

    const extraHeaders = options.headers;
    const timeoutMs = options.timeoutMs ?? 2000;
    const onError = options.onError;

    return (event: AuditEvent): void => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        const run = async () => {
            try {
                await fetch(url, {
                    method: 'POST',
                    headers: {
                        ...extraHeaders,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(toSafePayload(event)),
                    signal: controller.signal
                });
            } catch (err) {
                try {
                    onError?.(err);
                } catch {
                    // onError must not break the request either
                }
            } finally {
                clearTimeout(timeoutId);
            }
        };

        void run();
    };
}
