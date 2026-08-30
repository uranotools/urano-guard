import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHttpAuditSink } from '../src/core/HttpAuditSink';
import { AuditEvent } from '../src/types/audit';

afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
});

function sampleEvent(extra?: Record<string, unknown>): AuditEvent {
    return {
        requestId: 'req_1',
        action: 'BLOCK',
        allowed: false,
        riskScore: 80,
        threatCategories: ['PROMPT_INJECTION'],
        path: '/api/chat',
        method: 'POST',
        source: 'LOCAL_INSPECTOR',
        latencyMs: 12,
        ...extra
    } as AuditEvent;
}

describe('createHttpAuditSink', () => {
    it('requires a url', () => {
        expect(() => createHttpAuditSink({} as any)).toThrow(/url/);
        expect(() => createHttpAuditSink({ url: '' })).toThrow(/url/);
    });

    it('POSTs AuditEvent JSON without body or cookie keys', async () => {
        const fetchMock = vi.fn(async () => ({ ok: true }));
        vi.stubGlobal('fetch', fetchMock);

        const url = 'https://siem.example/ingest';
        const sink = createHttpAuditSink({ url });
        sink(sampleEvent({
            body: { password: 'secret', message: 'ignore previous' },
            cookie: 'session=abc123',
            cookies: { session: 'abc123' },
            Authorization: 'Bearer super-secret-token'
        }));

        await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

        expect(fetchMock).toHaveBeenCalledWith(
            url,
            expect.objectContaining({ method: 'POST' })
        );

        const init = fetchMock.mock.calls[0][1] as RequestInit;
        expect(init.method).toBe('POST');
        const headers = init.headers as Record<string, string>;
        expect(headers['Content-Type']).toBe('application/json');

        const posted = JSON.parse(String(init.body));
        expect(posted).not.toHaveProperty('body');
        expect(Object.keys(posted).some(key => /cookie/i.test(key))).toBe(false);
        expect(Object.keys(posted).some(key => /authorization/i.test(key))).toBe(false);
        expect(JSON.stringify(posted)).not.toContain('secret');
        expect(JSON.stringify(posted)).not.toContain('session=abc123');
        expect(posted.requestId).toBe('req_1');
        expect(posted.action).toBe('BLOCK');
        expect(posted.path).toBe('/api/chat');
        expect(posted.method).toBe('POST');
    });

    it('forwards optional headers and swallows fetch errors', async () => {
        const fetchMock = vi.fn(() => Promise.reject(new Error('siem down')));
        vi.stubGlobal('fetch', fetchMock);
        const onError = vi.fn();

        const sink = createHttpAuditSink({
            url: 'https://siem.example/hook',
            headers: { 'X-Webhook-Key': 'k' },
            timeoutMs: 500,
            onError
        });

        expect(() => sink(sampleEvent())).not.toThrow();
        await vi.waitFor(() => expect(onError).toHaveBeenCalled());
        expect(onError.mock.calls[0][0]).toBeInstanceOf(Error);

        const init = fetchMock.mock.calls[0][1] as RequestInit;
        const headers = init.headers as Record<string, string>;
        expect(headers['X-Webhook-Key']).toBe('k');
        expect(headers['Content-Type']).toBe('application/json');
    });

    it('does not throw when onError itself throws', async () => {
        vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('down'))));
        const sink = createHttpAuditSink({
            url: 'https://siem.example/hook',
            onError: () => {
                throw new Error('handler failed');
            }
        });
        expect(() => sink(sampleEvent())).not.toThrow();
        await new Promise(resolve => setTimeout(resolve, 20));
    });
});
