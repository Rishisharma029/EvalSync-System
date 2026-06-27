const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const LOG_FILE_PATH = path.join(__dirname, '../../audit.log');

// Helper to compute SHA-256 hash of an audit log entry
function calculateEntryHash(entry) {
  const data = (entry.index || 0) + '|' + 
               (entry.timestamp || entry.time || '') + '|' + 
               (entry.role || entry.actor || '') + '|' + 
               (entry.action || '') + '|' + 
               (entry.details || '') + '|' + 
               (entry.status || '') + '|' + 
               (entry.previousHash || '');
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Append an entry to the immutable ledger
function appendLedgerEntry(role, action, details, status = 'success') {
  let lastEntry = null;
  let index = 1;
  let previousHash = '0000000000000000000000000000000000000000000000000000000000000000';

  try {
    if (fs.existsSync(LOG_FILE_PATH)) {
      const logs = fs.readFileSync(LOG_FILE_PATH, 'utf8').trim().split('\n').filter(Boolean);
      if (logs.length > 0) {
        lastEntry = JSON.parse(logs[logs.length - 1]);
        index = (lastEntry.index || logs.length) + 1;
        previousHash = lastEntry.hash || calculateEntryHash(lastEntry);
      }
    }
  } catch (err) {
    console.error('[LEDGER ERROR] Failed to read last ledger entry:', err.message);
  }

  const entry = {
    index,
    timestamp: new Date().toISOString(),
    role: role || 'anonymous',
    action,
    details: details || '',
    status,
    previousHash
  };

  entry.hash = calculateEntryHash(entry);

  // Write to persistent audit.log file (JSON Lines format)
  try {
    fs.appendFileSync(LOG_FILE_PATH, JSON.stringify(entry) + '\n');
    console.log(`[AUDIT LEDGER] Block #${index} appended: ${entry.hash.substring(0, 16)}...`);
  } catch (err) {
    console.error('[LEDGER ERROR] Failed to write to audit.log', err);
  }

  return entry;
}

// Verify the integrity of the entire audit chain
function verifyLedgerIntegrity() {
  if (!fs.existsSync(LOG_FILE_PATH)) {
    return { verified: true, count: 0, corruptedIndex: -1, reason: 'Log file does not exist yet.' };
  }

  try {
    const logs = fs.readFileSync(LOG_FILE_PATH, 'utf8').trim().split('\n').filter(Boolean);
    let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < logs.length; i++) {
      const entry = JSON.parse(logs[i]);
      
      // 1. Verify previous hash link
      if (entry.previousHash !== expectedPrevHash) {
        return {
          verified: false,
          count: logs.length,
          corruptedIndex: entry.index || (i + 1),
          reason: `Previous hash mismatch at index ${entry.index || (i + 1)}. Expected: ${expectedPrevHash.substring(0, 12)}..., Found: ${entry.previousHash.substring(0, 12)}...`
        };
      }

      // 2. Verify current hash integrity
      const calculatedHash = calculateEntryHash(entry);
      if (entry.hash !== calculatedHash) {
        return {
          verified: false,
          count: logs.length,
          corruptedIndex: entry.index || (i + 1),
          reason: `Integrity hash mismatch at index ${entry.index || (i + 1)}. Block was altered.`
        };
      }

      expectedPrevHash = entry.hash;
    }

    return { verified: true, count: logs.length };
  } catch (err) {
    return { verified: false, count: 0, corruptedIndex: -1, reason: 'Failed to parse ledger file: ' + err.message };
  }
}

module.exports = {
  appendLedgerEntry,
  verifyLedgerIntegrity,
  calculateEntryHash
};
