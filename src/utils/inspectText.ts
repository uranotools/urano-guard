import { GuardRequestContext } from '../types/context';

export const INSPECTION_HEADER_ALLOWLIST = ['user-agent', 'referer', 'content-type', 'origin'];

const DEFAULT_MAX_BYTES = 256 * 1024;
const ZERO_WIDTH = /\u200b|\u200c|\u200d|\ufeff/g;

export interface NormalizeOptions {
    /** Map common leet/homoglyphs. Prompt-only: digits would break SQLi (OR 1=1). */
    leet?: boolean;
}

export function normalizeInspectionText(text: string, opts: NormalizeOptions = {}): string {
    let out = text.normalize('NFKC').replace(ZERO_WIDTH, '').replace(/\s+/g, ' ');
    if (opts.leet) {
        out = out
            .replace(/0/g, 'o')
            .replace(/1/g, 'i')
            .replace(/3/g, 'e')
            .replace(/@/g, 'a');
    }
    return out;
}

/** Strip short C-style and line SQL comments so split keywords still match. */
export function stripSqlComments(text: string): string {
    return text
        .replace(/\/\*[\s\S]{0,200}?\*\//g, '')
        .replace(/--[^\n]{0,200}/g, ' ');
}

export function stringifySafe(value: unknown, maxBytes = DEFAULT_MAX_BYTES): string {
    if (value == null) return '';
    if (typeof value === 'string') {
        return value.length > maxBytes ? value.slice(0, maxBytes) : value;
    }
    try {
        const encoded = JSON.stringify(value);
        if (!encoded) return '';
        return encoded.length > maxBytes ? encoded.slice(0, maxBytes) : encoded;
    } catch {
        return '';
    }
}

export function headerValue(
    headers: Record<string, string | string[] | undefined> | undefined,
    name: string
): string {
    if (!headers) return '';
    const direct = headers[name] ?? headers[name.toLowerCase()];
    if (direct == null) return '';
    return String(Array.isArray(direct) ? direct[0] : direct);
}

export function collectInspectionText(
    context: GuardRequestContext,
    maxBytes = DEFAULT_MAX_BYTES
): string {
    const parts: string[] = [];
    if (context.path) parts.push(context.path);
    const query = stringifySafe(context.query, maxBytes);
    if (query && query !== '{}' && query !== '""') parts.push(query);
    parts.push(stringifySafe(context.body, maxBytes));
    if (context.rawBody) parts.push(context.rawBody.length > maxBytes ? context.rawBody.slice(0, maxBytes) : context.rawBody);
    for (const key of INSPECTION_HEADER_ALLOWLIST) {
        const value = headerValue(context.headers, key);
        if (value) parts.push(value);
    }
    const joined = parts.join('\n');
    const clipped = joined.length > maxBytes * 2 ? joined.slice(0, maxBytes * 2) : joined;
    return normalizeInspectionText(clipped);
}
