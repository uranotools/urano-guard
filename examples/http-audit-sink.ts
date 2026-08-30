/**
 * POST each AuditEvent to a SIEM or webhook. Fire-and-forget; failures are swallowed.
 * The payload is the safe AuditEvent (no request body, cookies, or Authorization).
 *
 *   SIEM_URL=https://siem.example/ingest npx tsx examples/http-audit-sink.ts
 */
import { createUranoGuard, createHttpAuditSink } from '../src';

const guard = createUranoGuard({
    auditLogger: createHttpAuditSink({ url: process.env.SIEM_URL })
});

void guard;
