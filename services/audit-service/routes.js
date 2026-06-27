const express = require('express');
const { body, validationResult } = require('express-validator');
const fs = require('fs');
const path = require('path');
const { appendLedgerEntry, verifyLedgerIntegrity } = require('./ledger');

const router = express.Router();
const LOG_FILE_PATH = path.join(__dirname, '../../audit.log');

// Local auth helper (middleware version)
function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// Allowlist of permissible actions to prevent log injection
const ALLOWED_AUDIT_ACTIONS = new Set([
  'settings-change', 'queue-reset', 'queue-control', 'scale-worker',
  'system-reset', 'chaos-test', 'logout'
]);

// 1. Post new audit event to ledger
router.post(
  '/log',
  checkAuth,
  [
    body('action').trim().notEmpty().withMessage('Action is required'),
    body('details').trim().escape()
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const roleKey = req.session.user.roleKey;
    const { action, details } = req.body;

    if (!ALLOWED_AUDIT_ACTIONS.has(action)) {
      appendLedgerEntry(roleKey, 'audit-rejected', `Rejected unknown audit action: ${action}`, 'failure');
      return res.status(400).json({ error: 'Unknown audit action' });
    }

    const entry = appendLedgerEntry(roleKey, action, details, 'success');
    return res.status(200).json({ success: true, entry });
  }
);

// 2. Fetch ledger history
router.get('/ledger', checkAuth, (req, res) => {
  try {
    if (!fs.existsSync(LOG_FILE_PATH)) {
      return res.status(200).json({ entries: [] });
    }
    const lines = fs.readFileSync(LOG_FILE_PATH, 'utf8').trim().split('\n').filter(Boolean);
    const entries = lines.map(line => JSON.parse(line)).reverse();
    return res.status(200).json({ entries });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to read audit log: ' + err.message });
  }
});

// 3. Verify ledger cryptographic integrity
router.get('/verify', checkAuth, (req, res) => {
  const result = verifyLedgerIntegrity();
  return res.status(200).json(result);
});

module.exports = router;
