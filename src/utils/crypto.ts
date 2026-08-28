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
        const cleanSignature = signature.replace(/^(sha256=|sha1=)/i, '');
        
        return crypto.timingSafeEqual(
            Buffer.from(cleanSignature, 'hex'),
            Buffer.from(expected, 'hex')
        );
    } catch {
        return false;
    }
}