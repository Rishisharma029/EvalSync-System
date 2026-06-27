const express = require('express');
const crypto = require('crypto');

const router = express.Router();

// Mock database for submissions
const submissionMetadataDB = new Map();

// HSM Key Vault Simulation (FIPS 140-2 compliant key storage)
const HSM_KEYS = {
  activeKeyId: 'hsm-key-v1',
  keys: {
    'hsm-key-v1': 'cbse-evalsync-hsm-fips-140-2-secure-payload-signing-key-token'
  }
};

// Simple session DLP tracking (Maximum 5 downloads per session)
const dlpSessionDownloads = new Map();

// Helper: check auth
function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// HSM Secure Signing Function
function hsmGenerateSignature(payload) {
  const activeKey = HSM_KEYS.keys[HSM_KEYS.activeKeyId];
  return crypto.createHmac('sha256', activeKey).update(payload).digest('hex');
}

// 1. Submit scanned scripts and verify integrity
router.post('/upload', checkAuth, (req, res) => {
  const { studentRoll, subject, setCode, filesCount, filesSize, regionalCode } = req.body;

  if (!studentRoll || !subject || !setCode) {
    return res.status(400).json({ error: 'Missing required metadata: roll, subject, setCode' });
  }

  // 1. Perform Script Integrity checks (Magic numbers and scans checks)
  const scanQuality = Math.random() > 0.05 ? 'High (300 DPI)' : 'Low Resolution';
  const integrityReport = {
    missingPages: 0,
    duplicatePages: 0,
    blankPages: Math.random() < 0.1 ? 1 : 0, // 10% chance of blank page
    orientationOk: true,
    resolution: scanQuality,
    watermarkVerified: true,
    corruptedScan: false
  };

  if (integrityReport.blankPages > 0) {
    integrityReport.warning = 'Warning: Blank page detected on page 4 of the submission.';
  }

  // 2. Generate cryptographically secure submission info
  const submissionId = `CBSE-2024-${subject.toUpperCase().substring(0, 4)}-${regionalCode || 'DEL'}-${Date.now().toString().slice(-6)}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  const payloadHash = crypto.createHash('sha256').update(JSON.stringify(req.body) + Date.now()).digest('hex');
  
  // FIPS HSM Signature signing
  const signature = hsmGenerateSignature(payloadHash);

  // 3. Map to Object Storage (simulating S3 bucket configuration)
  const objectStorageBucket = 'cbse-evalsync-vault';
  const objectStorageKey = `submissions/${regionalCode || 'DEL'}/${subject.toLowerCase()}/${submissionId}.pdf`;
  const s3Url = `https://${objectStorageBucket}.s3.ap-south-1.amazonaws.com/${objectStorageKey}`;

  const submissionRecord = {
    id: submissionId,
    hash: payloadHash,
    signature,
    keyVersion: HSM_KEYS.activeKeyId,
    subject,
    setCode,
    roll: studentRoll,
    filesCount: filesCount || 1,
    filesSize: filesSize || 1024 * 1024 * 3, // default 3MB
    storageUrl: s3Url,
    uploadedAt: new Date().toISOString(),
    status: 'Uploaded',
    integrity: integrityReport,
    version: 1,
    history: [
      { version: 1, status: 'Uploaded', time: new Date().toISOString(), actor: req.session.user.email }
    ]
  };

  // Save to metadata DB
  submissionMetadataDB.set(submissionId, submissionRecord);

  return res.status(200).json({
    message: 'Script submitted and encrypted successfully',
    submission: submissionRecord
  });
});

// 2. Generate signed short-lived download token (signed via HSM, expires in 60s)
router.get('/:id/request-download', checkAuth, (req, res) => {
  const { id } = req.params;
  if (!submissionMetadataDB.has(id)) {
    return res.status(404).json({ error: 'Submission not found' });
  }

  const userEmail = req.session.user.email;
  const expiresAt = Date.now() + 60 * 1000; // 1 minute expiration
  const tokenPayload = `${id}|${userEmail}|${expiresAt}`;
  const downloadToken = hsmGenerateSignature(tokenPayload);

  return res.status(200).json({
    downloadToken,
    expiresAt,
    url: `/api/v1/submissions/${id}/download?token=${downloadToken}&expires=${expiresAt}&user=${encodeURIComponent(userEmail)}`
  });
});

// 3. Download / fetch script details (guarded by Signed URLs and DLP limits)
router.get('/:id/download', checkAuth, (req, res) => {
  const { id } = req.params;
  const { token, expires, user } = req.query;

  // 1. Verify URL parameters are present
  if (!token || !expires || !user) {
    return res.status(403).json({ error: 'Access Denied: Missing Signed URL tokens.', code: 'SIGNED_TOKEN_MISSING' });
  }

  // 2. Verify token expiration
  if (Date.now() > parseInt(expires)) {
    return res.status(403).json({ error: 'Access Denied: Signed URL token has expired.', code: 'SIGNED_TOKEN_EXPIRED' });
  }

  // 3. Verify HSM token signature
  const tokenPayload = `${id}|${user}|${expires}`;
  const expectedToken = hsmGenerateSignature(tokenPayload);
  
  // Constant time comparison block to prevent timing attacks
  const tokenBuffer = Buffer.from(token);
  const expectedBuffer = Buffer.from(expectedToken);
  const isSignatureValid = tokenBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(tokenBuffer, expectedBuffer);

  if (!isSignatureValid) {
    return res.status(403).json({ error: 'Access Denied: Invalid HSM signature.', code: 'SIGNED_TOKEN_INVALID' });
  }

  // 4. Enforce Data Loss Prevention (DLP) limits (Limit 5 downloads per session)
  const dlpKey = req.session.id || user;
  const downloadsCount = dlpSessionDownloads.get(dlpKey) || 0;

  if (downloadsCount >= 5) {
    return res.status(429).json({
      error: 'DLP Incident: Bulk downloads blocked to prevent script leakage. Download quota exceeded (Max 5/session).',
      code: 'DLP_LIMIT_EXCEEDED'
    });
  }

  dlpSessionDownloads.set(dlpKey, downloadsCount + 1);

  const record = submissionMetadataDB.get(id);
  if (!record) {
    return res.status(404).json({ error: 'Submission not found' });
  }

  return res.status(200).json({
    success: true,
    downloadsRemaining: 5 - (downloadsCount + 1),
    record
  });
});

// Default details fallback (Requires base permission check)
router.get('/:id', checkAuth, (req, res) => {
  const record = submissionMetadataDB.get(req.params.id);
  if (!record) {
    return res.status(404).json({ error: 'Submission not found' });
  }
  return res.status(200).json(record);
});

module.exports = router;
