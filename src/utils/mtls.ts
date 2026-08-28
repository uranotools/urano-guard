import * as tls from 'tls';
import * as https from 'https';

export interface MtlsConfig {
    /** PEM del certificado del cliente (lado del SDK que hace fetch al upstream) */
    clientCert?: string;
    /** PEM de la clave privada del cliente */
    clientKey?: string;
    /** PEM del CA raíz de confianza (para verificar el servidor upstream) */
    caCert?: string;
    /** Si true, verifica el certificado del servidor upstream (default: true) */
    rejectUnauthorized?: boolean;
}

/**
 * Crea un agente HTTPS con mTLS habilitado para comunicación segura
 * entre el SDK y el servidor upstream / Agente Urano.
 * Úsalo pasándolo como option al fetch en lugar del fetch nativo.
 */
export function createMtlsAgent(config: MtlsConfig): https.Agent {
    return new https.Agent({
        cert: config.clientCert,
        key: config.clientKey,
        ca: config.caCert,
        rejectUnauthorized: config.rejectUnauthorized !== false
    });
}

/**
 * Extrae el Common Name (CN) del certificado de cliente presentado
 * en una petición TLS (para validación de identidad en lado servidor).
 * 
 * @param req - Petición Node.js TLS / HTTPS nativa
 * @returns El CN del certificado del cliente o null si no hay cert
 */
export function extractClientCertCN(req: any): string | null {
    const socket = req.socket as tls.TLSSocket;
    if (!socket || typeof socket.getPeerCertificate !== 'function') return null;

    const cert = socket.getPeerCertificate();
    if (!cert || !cert.subject) return null;

    const cn = cert.subject.CN;
    return (Array.isArray(cn) ? cn[0] : cn) || null;
}

/**
 * Valida que la petición tenga un certificado de cliente válido y
 * que su CN coincida con los permitidos.
 */
export function validateClientCert(req: any, allowedCNs: string[]): boolean {
    const cn = extractClientCertCN(req);
    if (!cn) return false;
    return allowedCNs.includes(cn);
}
