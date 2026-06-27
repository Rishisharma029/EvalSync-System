const express = require('express');

const router = express.Router();

// Mock distributed queue structures
const queues = {
  incoming: [],
  priority: [],
  retry: [],
  dlq: [],
  delayed: [],
  batch: []
};

// Queue configuration stats
let lagMs = 45;
let throughputRps = 12.4;

function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// 1. Get queue latency & health metrics
router.get('/metrics', checkAuth, (req, res) => {
  // Add minor variations to metrics for real-time telemetry feel
  lagMs = Math.max(10, lagMs + Math.floor(Math.random() * 9) - 4);
  throughputRps = Math.max(0.5, throughputRps + (Math.random() * 2) - 1);

  return res.status(200).json({
    lagMs,
    throughputRps,
    depth: {
      incoming: queues.incoming.length,
      priority: queues.priority.length,
      retry: queues.retry.length,
      dlq: queues.dlq.length,
      delayed: queues.delayed.length,
      batch: queues.batch.length,
      total: Object.values(queues).reduce((sum, q) => sum + q.length, 0)
    }
  });
});

// 2. Enqueue an item into a specific queue channel
router.post('/enqueue', checkAuth, (req, res) => {
  const { submission, priorityLevel, channel } = req.body;
  if (!submission) return res.status(400).json({ error: 'Submission item required' });

  const targetChannel = channel || 'incoming';
  if (!queues[targetChannel]) return res.status(400).json({ error: `Invalid queue channel: ${targetChannel}` });

  const queueItem = {
    submission,
    priority: priorityLevel || 3, // 1 (highest) to 5 (lowest)
    enqueuedAt: new Date().toISOString()
  };

  queues[targetChannel].push(queueItem);
  return res.status(200).json({ success: true, channel: targetChannel, depth: queues[targetChannel].length });
});

// 3. Dequeue an item (used by worker pollers)
router.post('/dequeue', checkAuth, (req, res) => {
  const { channel } = req.body;
  const targetChannel = channel || 'incoming';
  if (!queues[targetChannel]) return res.status(400).json({ error: `Invalid queue channel: ${targetChannel}` });

  if (queues[targetChannel].length === 0) {
    return res.status(200).json({ submission: null });
  }

  // Dequeue FIFO or by priority if channel is 'priority'
  let item = null;
  if (targetChannel === 'priority') {
    queues.priority.sort((a, b) => a.priority - b.priority);
    item = queues.priority.shift();
  } else {
    item = queues[targetChannel].shift();
  }

  return res.status(200).json({ item });
});

// 4. Force Retry a DLQ item
router.post('/dlq/retry-all', checkAuth, (req, res) => {
  const count = queues.dlq.length;
  while (queues.dlq.length > 0) {
    const item = queues.dlq.shift();
    queues.incoming.push(item);
  }
  return res.status(200).json({ success: true, retriedCount: count });
});

module.exports = router;
