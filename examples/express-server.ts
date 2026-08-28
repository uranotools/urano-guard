import express from 'express';
import { createUranoGuard } from '../src';

const app = express();
app.use(express.json());

// 🛡️ Inicialización de Urano Guard
const guard = createUranoGuard({
    agentWebhookUrl: 'https://api.urano.cloud/v1/webhook/mcp_cyber-gateway/my_chan_123',
    securityMode: 'block_threats',
    enableCache: true,
    cacheTtlMs: 60000,
    onThreatDetected: (threat, req) => {
        console.warn(`[ALERTA DE SEGURIDAD] ${threat.category} (${threat.severity}): ${threat.summary}`);
    }
});

// Middleware global o por ruta
app.post('/api/webhook/incoming', guard.express(), (req, res) => {
    // Si llega aquí, el tráfico está limpio y verificado
    res.json({ success: true, payload: req.body });
});

app.listen(3000, () => {
    console.log('🚀 Servidor protegido con Urano Guard en http://localhost:3000');
});