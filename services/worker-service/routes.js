const express = require('express');

const router = express.Router();

// Simulated database of registered workers
const workersMetadata = new Map();

// Mock examiner profiles for script assignment
const examinersReputation = {
  'evaluator@cbse.gov.in': { name: 'Rajan Mehta', center: 'DEL-0412', subject: 'Mathematics', accuracy: 0.98, consistency: 0.96, speedMs: 4200, rating: 4.8 },
  'admin@cbse.gov.in': { name: 'Priya Singh', center: 'MUM-1204', subject: 'Physics', accuracy: 0.99, consistency: 0.98, speedMs: 3800, rating: 4.9 },
  'superadmin@cbse.gov.in': { name: 'Dr. Arvind Kumar', center: 'DEL-8874', subject: 'Chemistry', accuracy: 0.97, consistency: 0.95, speedMs: 4500, rating: 4.7 }
};

function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// 1. Worker Heartbeat and Registration
router.post('/register', checkAuth, (req, res) => {
  const { id, isScaled, status, cpuUsage, memUsage } = req.body;
  if (!id) return res.status(400).json({ error: 'Worker ID required' });

  const record = {
    id,
    isScaled: !!isScaled,
    status: status || 'idle',
    cpu: cpuUsage || Math.floor(Math.random() * 15 + 5),
    mem: memUsage || Math.floor(Math.random() * 10 + 30),
    lastHeartbeat: new Date().toISOString()
  };

  workersMetadata.set(id, record);
  return res.status(200).json({ success: true, worker: record });
});

// 2. Fetch active worker nodes and telemetry metrics
router.get('/metrics', checkAuth, (req, res) => {
  // Prune inactive/stale workers (stale after 10 seconds of no heartbeat)
  const now = Date.now();
  const list = [];
  let totalCpu = 0;
  let activeCount = 0;

  for (const [id, w] of workersMetadata.entries()) {
    const diff = now - new Date(w.lastHeartbeat).getTime();
    if (diff > 10000) {
      w.status = 'OFFLINE';
    }
    list.push(w);
    if (w.status !== 'OFFLINE') {
      totalCpu += w.cpu;
      activeCount++;
    }
  }

  return res.status(200).json({
    poolSize: list.length,
    activeCount,
    avgCpu: activeCount > 0 ? Math.round(totalCpu / activeCount) : 5,
    workers: list
  });
});

// 3. Intelligent script assignment using the Examiner Reputation Engine
router.post('/assign-script', checkAuth, (req, res) => {
  const { scriptId, subject, scriptCenter } = req.body;
  const userEmail = req.session.user.email;

  const profile = examinersReputation[userEmail] || {
    name: req.session.user.name,
    center: req.session.user.center,
    subject: 'Mathematics',
    accuracy: 0.95,
    consistency: 0.92,
    speedMs: 5000,
    rating: 4.5
  };

  // 1. Check for Conflicts of Interest (DPDP / CBSE Exam Integrity Safeguards)
  if (scriptCenter === profile.center) {
    return res.status(409).json({
      assigned: false,
      reason: 'Conflict of Interest: Script originates from the same examination center as the evaluator.'
    });
  }

  // 2. Check Subject Expertise matching
  if (subject && subject.toLowerCase() !== profile.subject.toLowerCase()) {
    return res.status(400).json({
      assigned: false,
      reason: `Subject Mismatch: Evaluator's expertise is in ${profile.subject}, but the script is for ${subject}.`
    });
  }

  // 3. Evaluate Workload Balance
  const score = Math.round(profile.accuracy * 0.4 + profile.consistency * 0.3 + (1 - profile.speedMs / 10000) * 0.3);

  return res.status(200).json({
    assigned: true,
    evaluator: profile.name,
    score,
    accuracy: (profile.accuracy * 100).toFixed(0) + '%',
    speed: (profile.speedMs / 1000).toFixed(1) + 's/script',
    workloadApproved: true
  });
});

module.exports = router;
