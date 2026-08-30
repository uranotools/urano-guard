/**
 * Attach in-process Prometheus metrics and scrape them.
 *
 *   const metrics = createPrometheusMetrics();
 *   const guard = createUranoGuard({ metrics });
 *
 * Node HTTP:
 *   if (req.url === '/metrics') return void guard.metricsHandler()(req, res);
 *
 * Express:
 *   app.get('/metrics', guard.metricsHandler());
 *
 * Or pull the text yourself:
 *   const text = guard.prometheus();
 */
import http from 'http';
import { createUranoGuard, createPrometheusMetrics } from '../src';

const metrics = createPrometheusMetrics();
const guard = createUranoGuard({
    securityMode: 'block_threats',
    metrics,
    auditLogger: 'json'
});

const inspect = guard.http();

http.createServer(async (req, res) => {
    if (req.method === 'GET' && (req.url || '').split('?')[0] === '/metrics') {
        guard.metricsHandler()(req, res);
        return;
    }
    const allowed = await inspect(req, res);
    if (!allowed) return;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
}).listen(Number(process.env.METRICS_PORT || 3001), () => {
    console.log('Scrape http://127.0.0.1:3001/metrics');
});
