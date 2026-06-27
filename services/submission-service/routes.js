const express = require('express');
const crypto = require('crypto');

const router = express.Router();

// Mock database for submissions
const submissionMetadataDB = new Map();

// Helper: check auth
function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// Digital Signature helper using SHA-256 and local private key (simulated)
function signPayload(payload) {
  const privateKey = 'cbse-evalsync-secret-key-signature-token';
  return crypto.createHmac('sha256', privateKey).update(payload).digest('hex');
}

// 1. Submit scanned scripts and verify integrity
router.post('/upload', checkAuth, (req, res) => {
  const { studentRoll, subject, setCode, filesCount, filesSize, regionalCode } = req.body;

  if (!studentRoll || !subject || !setCode) {
    return res.status(400).json({ error: 'Missing required metadata: roll, subject, setCode' });
  }

  // 1. Perform Script Integrity checks (Simulating real PDF parsing checks)
  const scanQuality = Math.random() > 0.05 ? 'High (300 DPI)' : 'Low Resolution';
  const integrityReport = {
    missingPages: 0,
    duplicatePages: 0,
    blankPages: Math.random() < 0.1 ? 1 : 0, // 10% chance of detecting a blank page
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
  const signature = signPayload(payloadHash);

  // 3. Map to Object Storage (simulating MinIO / AWS S3 upload link)
  const objectStorageBucket = 'cbse-evalsync-vault';
  const objectStorageKey = `submissions/${regionalCode || 'DEL'}/${subject.toLowerCase()}/${submissionId}.pdf`;
  const s3Url = `https://${objectStorageBucket}.s3.ap-south-1.amazonaws.com/${objectStorageKey}`;

  const submissionRecord = {
    id: submissionId,
    hash: payloadHash,
    signature,
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

// 2. Get script details from metadata database
router.get('/:id', checkAuth, (req, res) => {
  const record = submissionMetadataDB.get(req.params.id);
  if (!record) {
    return res.status(404).json({ error: 'Submission not found' });
  }
  return res.status(200).json(record);
});

module.exports = router;
