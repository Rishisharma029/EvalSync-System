const express = require('express');

const router = express.Router();

// Mock database geo-sync state
const dbReplicaState = {
  primary: { status: 'ONLINE', lagMs: 0, region: 'Mumbai' },
  delhi: { status: 'IN_SYNC', lagMs: 14, region: 'Delhi' },
  chennai: { status: 'IN_SYNC', lagMs: 28, region: 'Chennai' },
  bangalore: { status: 'IN_SYNC', lagMs: 42, region: 'Bangalore' }
};

let syncActive = true;
let totalSyncedRows = 247836;

function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// 1. Fetch geo-sync states
router.get('/status', checkAuth, (req, res) => {
  // Add minor variations to replicate networking lag
  if (syncActive) {
    dbReplicaState.delhi.lagMs = Math.max(5, dbReplicaState.delhi.lagMs + Math.floor(Math.random() * 5) - 2);
    dbReplicaState.chennai.lagMs = Math.max(10, dbReplicaState.chennai.lagMs + Math.floor(Math.random() * 7) - 3);
    dbReplicaState.bangalore.lagMs = Math.max(15, dbReplicaState.bangalore.lagMs + Math.floor(Math.random() * 9) - 4);
  }

  return res.status(200).json({
    syncActive,
    totalSyncedRows,
    replicas: dbReplicaState
  });
});

// 2. Perform failover test (Mumbai down, promoting Delhi)
router.post('/failover', checkAuth, (req, res) => {
  dbReplicaState.primary.status = 'OFFLINE';
  dbReplicaState.delhi.status = 'FAILOVER_ACTIVE';

  setTimeout(() => {
    // Failover complete -> Delhi promoted
    dbReplicaState.primary = { status: 'ONLINE', lagMs: 0, region: 'Delhi' };
    dbReplicaState.delhi.status = 'IN_SYNC';
    dbReplicaState.delhi.lagMs = 12;
  }, 3500);

  return res.status(200).json({
    message: 'Failover procedure initiated: Promoting Replica 1 (Delhi) to Primary DB...',
    status: dbReplicaState
  });
});

// 3. Resume database replication sync
router.post('/sync/resume', checkAuth, (req, res) => {
  syncActive = true;
  dbReplicaState.delhi.status = 'IN_SYNC';
  dbReplicaState.chennai.status = 'IN_SYNC';
  dbReplicaState.bangalore.status = 'IN_SYNC';
  return res.status(200).json({ message: 'Geo-replication sync resumed.' });
});

module.exports = router;
