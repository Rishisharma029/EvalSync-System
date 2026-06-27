const express = require('express');

const router = express.Router();

function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// 1. Prometheus Scraping Endpoint
router.get('/prometheus', (req, res) => {
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  const cpu = 30 + Math.floor(Math.random() * 20);
  const mem = 45 + Math.floor(Math.random() * 5);
  const throughput = 12.4 + (Math.random() * 2 - 1);
  const lag = 6.4 + (Math.random() * 1 - 0.5);

  const metrics = `
# HELP evalsync_cpu_utilization CPU utilization percentage
# TYPE evalsync_cpu_utilization gauge
evalsync_cpu_utilization ${cpu}

# HELP evalsync_memory_utilization Memory utilization percentage
# TYPE evalsync_memory_utilization gauge
evalsync_memory_utilization ${mem}

# HELP evalsync_throughput_rps Rate of processed scripts per second
# TYPE evalsync_throughput_rps gauge
evalsync_throughput_rps ${throughput.toFixed(2)}

# HELP evalsync_queue_lag_seconds Average latency lag in queue delivery
# TYPE evalsync_queue_lag_seconds gauge
evalsync_queue_lag_seconds ${lag.toFixed(2)}
  `.trim();

  return res.status(200).send(metrics);
});

// 2. Fetch OpenTelemetry trace spans (simulated JSON structure)
router.get('/traces', checkAuth, (req, res) => {
  const correlationId = req.headers['x-correlation-id'] || 'corr-' + Math.random().toString(36).substring(2, 9);
  
  return res.status(200).json({
    correlationId,
    spans: [
      { spanId: 'gateway-span', serviceName: 'api-gateway', name: 'POST /api/v1/submissions/upload', durationMs: 12 },
      { spanId: 'auth-span', parentSpanId: 'gateway-span', serviceName: 'auth-service', name: 'verifySession', durationMs: 4 },
      { spanId: 'submission-span', parentSpanId: 'gateway-span', serviceName: 'submission-service', name: 'integrityCheck', durationMs: 82 },
      { spanId: 'queue-span', parentSpanId: 'submission-span', serviceName: 'queue-service', name: 'enqueueSubmission', durationMs: 18 },
      { spanId: 'db-span', parentSpanId: 'submission-span', serviceName: 'db-service', name: 'syncMetadata', durationMs: 24 }
    ]
  });
});

module.exports = router;
