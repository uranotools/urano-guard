import { GuardRequestContext } from '../types/context';

export const INSPECTION_HEADER_ALLOWLIST = ['user-agent', 'referer', 'content-type', 'origin'];

const DEFAULT_MAX_BYTES = 256 * 1024;
const ZERO_WIDTH = /\u200b|\u200c|\u200d|\ufeff/g;

/** Cyrillic / Greek / Latin lookalikes → ASCII. Letter-only so SQLi tautologies stay intact. */
const HOMOGLYPH: Record<string, string> = {
    '\u0430': 'a', '\u03B1': 'a', '\u0410': 'a',
    '\u0435': 'e', '\u03B5': 'e', '\u0415': 'e',
    '\u043E': 'o', '\u03BF': 'o', '\u041E': 'o',
    '\u0440': 'p', '\u03C1': 'p', '\u0420': 'p',
    '\u0441': 'c', '\u0421': 'c',
    '\u0443': 'y', '\u03C5': 'y', '\u0423': 'y',
    '\u0445': 'x', '\u03C7': 'x', '\u0425': 'x',
    '\u0456': 'i', '\u03B9': 'i', '\u0131': 'i', '\u0406': 'i',
    '\u0455': 's',
    '\u03BD': 'v',
    '\u03C4': 't'
};

export interface NormalizeOptions {
    /** Map common leet/homoglyphs. Prompt-only: digits would break SQLi (OR 1=1). */
    leet?: boolean;
}

function foldHomoglyphs(text: string): string {
    let out = '';
    for (const ch of text) {
        out += HOMOGLYPH[ch] ?? ch;
    }
    return out;
}

export function normalizeInspectionText(text: string, opts: NormalizeOptions = {}): string {
    let out = foldHomoglyphs(text.normalize('NFKC').replace(ZERO_WIDTH, '')).replace(/\s+/g, ' ');
    if (opts.leet) {
        out = out
            .replace(/0/g, 'o')
            .replace(/1/g, 'i')
            .replace(/3/g, 'e')
            .replace(/@/g, 'a');
    }
    return out;
}

/** Scan only this many leading bytes — keeps entity work linear and bounded. */
const HTML_ENTITY_PREFIX_BYTES = 8192;
const HTML_ENTITY_MAX_DECODE = 96;
/** Max chars between `&` and `;` (e.g. `#x73`, `lt`). */
const HTML_ENTITY_MAX_LEN = 10;

const NAMED_ENTITIES: Record<string, string> = {
    lt: '<',
    gt: '>',
    amp: '&',
    quot: '"',
    apos: "'"
};

function decodeOneEntity(body: string): string | null {
    if (!body) return null;
    if (body.charCodeAt(0) === 35) {
        let code: number;
        const hex = body.charCodeAt(1) === 120 || body.charCodeAt(1) === 88;
        if (hex) {
            const digits = body.slice(2);
            if (!digits || digits.length > 6) return null;
            for (let i = 0; i < digits.length; i++) {
                const c = digits.charCodeAt(i);
                const ok = (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
                if (!ok) return null;
            }
            code = parseInt(digits, 16);
        } else {
            const digits = body.slice(1);
            if (!digits || digits.length > 7) return null;
            for (let i = 0; i < digits.length; i++) {
                const c = digits.charCodeAt(i);
                if (c < 48 || c > 57) return null;
            }
            code = parseInt(digits, 10);
        }
        if (!Number.isFinite(code) || code < 9 || code > 0x10ffff) return null;
        if (code >= 0xd800 && code <= 0xdfff) return null;
        try {
            return String.fromCodePoint(code);
        } catch {
            return null;
        }
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? null;
}

/**
 * Decode a bounded prefix of HTML entities (`&#x73;` → `s`, `&lt;` → `<`).
 * Linear scan, fixed look-ahead — no regex (avoids ReDoS).
 */
export function decodeHtmlEntitiesBounded(text: string): string {
    const limit = Math.min(text.length, HTML_ENTITY_PREFIX_BYTES);
    let out = '';
    let decoded = 0;
    let i = 0;
    while (i < limit) {
        const ch = text[i];
        if (ch === '&' && decoded < HTML_ENTITY_MAX_DECODE) {
            const maxJ = Math.min(limit, i + 1 + HTML_ENTITY_MAX_LEN);
            let semi = -1;
            for (let j = i + 1; j < maxJ; j++) {
                const c = text[j];
                if (c === ';') {
                    semi = j;
                    break;
                }
                if (c === '&' || c === '<' || c === ' ' || c === '\n' || c === '\r' || c === '\t') break;
            }
            if (semi !== -1) {
                const replacement = decodeOneEntity(text.slice(i + 1, semi));
                if (replacement !== null) {
                    out += replacement;
                    decoded++;
                    i = semi + 1;
                    continue;
                }
            }
        }
        out += ch;
        i++;
    }
    if (limit < text.length) out += text.slice(limit);
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
    return decodeHtmlEntitiesBounded(normalizeInspectionText(clipped));
}
