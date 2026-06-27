const express = require('express');
const { appendLedgerEntry } = require('../audit-service/ledger');

const router = express.Router();

function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// Global Policy config
const policies = {
  queueThreshold: 1000,
  workerMaxIdleMinutes: 30,
  criticalCpuLimit: 90,
  autoScalingMode: 'AUTOMATIC'
};

// Feature Flags
const featureFlags = {
  enableAI: true,
  disablePrediction: false,
  enableQueueMonitor: true,
  enableRegionSimulation: true
};

// SOC Telemetry state
const socTelemetry = {
  securityScore: 98,
  threatLevel: 'LOW',
  blockedRequests: 1422,
  failedLogins: 14,
  malwareDetections: 0,
  integrityFailures: 0,
  activeAlerts: [
    { time: new Date().toLocaleTimeString(), type: 'INFO', msg: 'mTLS handshake complete across Delhi DC.' },
    { time: new Date(Date.now() - 1000 * 60 * 30).toLocaleTimeString(), type: 'INFO', msg: 'Key rotation successfully completed for hsm-key-v1.' }
  ]
};

// Global helper to register blocked attempts (called from WAF middleware)
global.registerBlockedAttack = function (type, ip, path) {
  socTelemetry.blockedRequests++;
  socTelemetry.securityScore = Math.max(75, socTelemetry.securityScore - 1);
  socTelemetry.activeAlerts.unshift({
    time: new Date().toLocaleTimeString(),
    type: 'WARNING',
    msg: `WAF: Intercepted ${type.toUpperCase()} injection from IP ${ip} on path ${path}`
  });
  if (socTelemetry.activeAlerts.length > 20) socTelemetry.activeAlerts.pop();
};

// 1. Fetch system policies
router.get('/policies', checkAuth, (req, res) => {
  return res.status(200).json(policies);
});

// 2. Fetch feature flags
router.get('/flags', checkAuth, (req, res) => {
  return res.status(200).json(featureFlags);
});

// 3. Fetch security metrics
router.get('/security/metrics', checkAuth, (req, res) => {
  return res.status(200).json(socTelemetry);
});

// 4. Toggle feature flags
router.post('/flags/toggle', checkAuth, (req, res) => {
  const { flagKey, value } = req.body;
  if (featureFlags[flagKey] === undefined) {
    return res.status(400).json({ error: 'Unknown feature flag key' });
  }
  featureFlags[flagKey] = !!value;
  return res.status(200).json({ success: true, flags: featureFlags });
});

// 5. Simulate security attacks (Attack Simulation Center)
router.post('/simulate-attack', checkAuth, (req, res) => {
  const { attackType } = req.body;
  if (!attackType) return res.status(400).json({ error: 'Attack type is required' });

  const roleKey = req.session.user.roleKey;
  const ip = req.ip || '192.168.1.114';
  const correlationId = 'corr-' + Math.random().toString(36).substring(2, 9);
  
  // Set threat alerts & alter SOC scores
  socTelemetry.blockedRequests++;
  socTelemetry.securityScore = Math.max(50, socTelemetry.securityScore - 4);
  socTelemetry.threatLevel = socTelemetry.securityScore < 70 ? 'CRITICAL' : socTelemetry.securityScore < 85 ? 'HIGH' : 'MEDIUM';

  const alertMsg = {
    time: new Date().toLocaleTimeString(),
    type: 'CRITICAL',
    msg: `RASP/WAF: Blocked ${attackType.toUpperCase()} attempt from IP ${ip}. Incident reported.`
  };
  socTelemetry.activeAlerts.unshift(alertMsg);

  // Write immutable audit log entry
  appendLedgerEntry(roleKey, 'security-alert', `Blocked simulated ${attackType.toUpperCase()} exploit (Correlation ID: ${correlationId})`, 'blocked');

  return res.status(200).json({
    success: true,
    correlationId,
    blockedMsg: alertMsg.msg,
    metrics: socTelemetry
  });
});

// 6. AI Operations Assistant chat endpoint (queries live system stats)
router.post('/chat', checkAuth, (req, res) => {
  const { message, systemStats } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });

  const query = message.toLowerCase();
  let response = '';

  const queueLoad = systemStats ? systemStats.queueDepth : 0;
  const cpuLoad = systemStats ? systemStats.cpu : 35;
  const activeWorkers = systemStats ? systemStats.activeWorkers : 6;

  // 1. Bottleneck check
  if (query.includes('bottleneck') || query.includes('overload') || query.includes('delayed')) {
    if (queueLoad > 40) {
      response = `🚨 **Bottleneck Detected:** The system queue depth is currently at **${queueLoad}** items, which is elevated. The CPU load is at **${cpuLoad}%** with **${activeWorkers}** active workers. I recommend triggering the auto-scaler to spawn 4 additional worker pods immediately.`;
    } else {
      response = `🟢 **No Bottlenecks Detected:** All queues are currently clear (Queue Depth: **${queueLoad}**). Network latencies between Delhi, Mumbai, Chennai, and Bangalore regions are healthy under **45ms**. System operations are nominal.`;
    }
  }
  // 2. Load prediction
  else if (query.includes('predict') || query.includes('tomorrow') || query.includes('load')) {
    response = `📈 **AI Traffic Forecast (Next 24 Hours):**\n- **Expected Submissions:** ~48,200 script files.\n- **Peak Traffic Window:** 2:00 PM - 5:00 PM local time.\n- **Capacity recommendation:** Scale active worker pool from **${activeWorkers}** to **16** by 1:30 PM to avoid queue saturation.`;
  }
  // 3. Scaling advice
  else if (query.includes('scale') || query.includes('worker') || query.includes('idle')) {
    response = `⚙️ **Cluster Scaling Recommendation:**\n- The current worker count is **${activeWorkers}**.\n- Under current policy thresholds (*Queue > 1000 or CPU > 90%*), scaling is marked as **STABLE**.\n- Worker utilization is at **84%** average. No action is required.`;
  }
  // 4. Region status
  else if (query.includes('region') || query.includes('mumbai') || query.includes('delhi')) {
    response = `🌐 **Regional Deployment Telemetry:**\n- **Mumbai (Primary):** ONLINE (Latency: 0ms)\n- **Delhi (Replica 1):** ONLINE (Sync Lag: 12ms)\n- **Chennai (Replica 2):** ONLINE (Sync Lag: 28ms)\n- **Bangalore (Replica 3):** ONLINE (Sync Lag: 42ms)\n- Backup recovery nodes are in-sync. Failover paths are ready.`;
  }
  // 5. Security check
  else if (query.includes('security') || query.includes('waf') || query.includes('attack') || query.includes('threat')) {
    response = `🛡️ **SOC Operational Report:**\n- **Security Score:** **${socTelemetry.securityScore}/100**\n- **Threat Level:** **${socTelemetry.threatLevel}**\n- **Blocked Requests:** **${socTelemetry.blockedRequests}**\n- **Failed Logins:** **${socTelemetry.failedLogins}**\n- **RASP Status:** OPERATIONAL. All interfaces are locked.`;
  }
  // 6. Default fallback
  else {
    response = `🤖 **EvalSync AI Ops Assistant:**\nI can analyze system metrics and assist with operations:\n- Ask *"Which region is overloaded?"* or *"Are there bottlenecks?"*\n- Ask *"Predict tomorrow's traffic load"* or *"Recommend scaling"*`;
  }

  return res.status(200).json({ response });
});

module.exports = router;
