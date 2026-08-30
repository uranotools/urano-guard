import * as crypto from 'crypto';

export function verifyHmacSignature(
    payload: string | Buffer,
    signature: string,
    secret: string,
    algorithm = 'sha256'
): boolean {
    try {
        const hmac = crypto.createHmac(algorithm, secret);
        const expected = hmac.update(payload).digest('hex');
        const cleanSignature = String(signature).replace(/^(sha256=|sha1=)/i, '');
        const a = Buffer.from(cleanSignature, 'hex');
        const b = Buffer.from(expected, 'hex');
        if (a.length !== b.length || a.length === 0) return false;
        return crypto.timingSafeEqual(a, b);
    } catch {
        return false;
    }
}

export function signHmac(
    payload: string | Buffer,
    secret: string,
    algorithm = 'sha256'
): string {
    const digest = crypto.createHmac(algorithm, secret).update(payload).digest('hex');
    return `sha256=${digest}`;
}

export function sha256Hex(input: string | Buffer): string {
    return crypto.createHash('sha256').update(input).digest('hex');
}

export function randomToken(prefix = 'ht'): string {
    return `${prefix}_${crypto.randomBytes(16).toString('hex')}`;
}
