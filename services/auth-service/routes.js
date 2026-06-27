const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

const router = express.Router();

const ROLES_INFO = {
  evaluator: { email: 'evaluator@cbse.gov.in', name: 'Rajan Mehta', initials: 'RM', label: '👨‍🏫 Evaluator', description: 'Upload answer scripts & track your queue position' },
  admin: { email: 'admin@cbse.gov.in', name: 'Priya Singh', initials: 'PS', label: '🛡️ Admin', description: 'Queue control, DLQ recovery, DB sync & security audit' },
  superadmin: { email: 'superadmin@cbse.gov.in', name: 'Dr. Arvind Kumar', initials: 'AK', label: '👑 Super Admin', description: 'Full system access — all modules unlocked' },
  monitor: { email: 'monitor@cbse.gov.in', name: 'Sanjay Patel', initials: 'SP', label: '📡 Monitor', description: 'Read-only monitoring — all views, zero write access' },
  regionaladmin: { email: 'regionaladmin@cbse.gov.in', name: 'Meera Deshmukh', initials: 'MD', label: '📍 Regional Admin', description: 'Manage Delhi / Mumbai / Chennai regional scripts' },
  moderator: { email: 'moderator@cbse.gov.in', name: 'Anil Joshi', initials: 'AJ', label: '⚖️ Moderator', description: 'Evaluate disputes and verify script marks consistency' },
  auditor: { email: 'auditor@cbse.gov.in', name: 'Harsh Vardhan', initials: 'HV', label: '📋 Auditor', description: 'Verify cryptographic ledger signatures and compliance' },
  apiclient: { email: 'apiclient@cbse.gov.in', name: 'API System Client', initials: 'SC', label: '🔌 API Client', description: 'System-to-system access via signed JWT tokens' }
};

const getRolePasswordHash = (role) => {
  switch (role) {
    case 'evaluator':
      return process.env.EVALUATOR_PASSWORD_HASH || '$2b$10$z2QmXa7f9tSsmGfenpp48.5dhCr43kNG0NR4fOBpNj7z0xNCYgPla';
    case 'admin':
      return process.env.ADMIN_PASSWORD_HASH || '$2b$10$Nti5yGJgLBjUyS8rROTP5OAkvWbdO8pwK2MleV25NNGaJB2o2/j.O';
    case 'superadmin':
      return process.env.SUPERADMIN_PASSWORD_HASH || '$2b$10$Rfr2lahJKlVkTWDN.cgOCOAVVwFDzL7AfO8AH86eFot3IHFX9lPtK';
    case 'monitor':
      return process.env.MONITOR_PASSWORD_HASH || '$2b$10$QZ7OwANRRlkFm8Pq47Tz3uake3lMpnEAnfxjMVFhupFWXwTLSf9/O';
    case 'regionaladmin':
      return process.env.REGIONALADMIN_PASSWORD_HASH || '$2b$10$Nti5yGJgLBjUyS8rROTP5OAkvWbdO8pwK2MleV25NNGaJB2o2/j.O';
    case 'moderator':
      return process.env.MODERATOR_PASSWORD_HASH || '$2b$10$Nti5yGJgLBjUyS8rROTP5OAkvWbdO8pwK2MleV25NNGaJB2o2/j.O';
    case 'auditor':
      return process.env.AUDITOR_PASSWORD_HASH || '$2b$10$QZ7OwANRRlkFm8Pq47Tz3uake3lMpnEAnfxjMVFhupFWXwTLSf9/O';
    case 'apiclient':
      return process.env.APICLIENT_PASSWORD_HASH || '$2b$10$Rfr2lahJKlVkTWDN.cgOCOAVVwFDzL7AfO8AH86eFot3IHFX9lPtK';
    default:
      return null;
  }
};

// Simple in-memory progressive login tracker to mitigate brute force
const failedLogins = new Map();

// Verify current session
router.get('/session', (req, res) => {
  if (req.session && req.session.user) {
    return res.status(200).json({ user: req.session.user });
  }
  return res.status(401).json({ error: 'No active session' });
});

// Log In endpoint with validation, sanitization and Adaptive Risk calculation
router.post(
  '/login',
  [
    body('email').trim().isEmail().normalizeEmail().withMessage('A valid email address is required'),
    body('password').trim().notEmpty().withMessage('Password is required'),
    body('fingerprint').optional().trim(),
    body('location').optional().trim()
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { email, password, fingerprint, location } = req.body;

    // 1. Check brute force status / Progressive delay
    const failRecord = failedLogins.get(email) || { count: 0, lockUntil: 0 };
    if (failRecord.lockUntil > Date.now()) {
      const waitMins = Math.ceil((failRecord.lockUntil - Date.now()) / 60000);
      return res.status(423).json({
        error: `Account locked due to multiple login failures. Try again in ${waitMins} minutes.`,
        code: 'ACCOUNT_LOCKED'
      });
    }

    // 2. Identify which role matches this email
    const matchedRoleKey = Object.keys(ROLES_INFO).find(key => ROLES_INFO[key].email === email);
    if (!matchedRoleKey) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 3. Verify hashed password using bcrypt
    const hash = getRolePasswordHash(matchedRoleKey);
    const isMatch = hash && bcrypt.compareSync(password, hash);

    if (!isMatch) {
      failRecord.count++;
      if (failRecord.count >= 5) {
        failRecord.lockUntil = Date.now() + 15 * 60 * 1000; // 15 minutes lockout
      }
      failedLogins.set(email, failRecord);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset login failures on success
    failedLogins.delete(email);

    // 4. ADAPTIVE RISK ENGINE EVALUATION (Zero Trust Protection)
    let riskScore = 10; // base score

    // Simulate Location checks (e.g. impossible travel / geo-fencing check)
    if (location && location.toLowerCase() === 'suspicious') {
      riskScore += 45; // significant risk increase
    }

    // Simulate Fingerprint changes
    if (fingerprint && fingerprint === 'unknown_device_fingerprint') {
      riskScore += 25;
    }

    // IP reputation check simulation
    const userAgent = req.headers['user-agent'] || '';
    if (userAgent.includes('curl') || userAgent.includes('python-requests')) {
      riskScore += 30; // bot-like user agents
    }

    // Evaluate Risk Response
    if (riskScore >= 75) {
      return res.status(403).json({
        error: 'Login blocked: Suspicious access profile detected (Risk score: ' + riskScore + '). Access denied.',
        code: 'HIGH_RISK_BLOCKED',
        riskScore
      });
    }

    if (riskScore >= 50) {
      // Prompt for secondary validation (MFA/TOTP required)
      return res.status(202).json({
        message: 'MFA verification required',
        requireMfa: true,
        riskScore,
        tempEmail: email
      });
    }

    // Initialize session user
    const roleInfo = ROLES_INFO[matchedRoleKey];
    const user = {
      email: roleInfo.email,
      name: roleInfo.name,
      initials: roleInfo.initials,
      role: roleInfo.label,
      roleKey: matchedRoleKey,
      id: `${matchedRoleKey.toUpperCase()}-NET-${Math.floor(1000 + Math.random() * 9000)}-2024`,
      subject: 'Mathematics (041)',
      center: `DEL-${Math.floor(1000 + Math.random() * 9000)}`,
      riskScore
    };

    req.session.user = user;
    return res.status(200).json({ user, riskScore });
  }
);

// MFA Validation Verification Endpoint (TOTP Simulator)
router.post('/verify-mfa', (req, res) => {
  const { email, totpCode } = req.body;
  if (!email || !totpCode) {
    return res.status(400).json({ error: 'Email and MFA Code are required' });
  }

  if (totpCode !== '123456') { // Mock verification token
    return res.status(401).json({ error: 'Invalid MFA verification code' });
  }

  const matchedRoleKey = Object.keys(ROLES_INFO).find(key => ROLES_INFO[key].email === email);
  if (!matchedRoleKey) {
    return res.status(404).json({ error: 'User not found' });
  }

  const roleInfo = ROLES_INFO[matchedRoleKey];
  const user = {
    email: roleInfo.email,
    name: roleInfo.name,
    initials: roleInfo.initials,
    role: roleInfo.label,
    roleKey: matchedRoleKey,
    id: `${matchedRoleKey.toUpperCase()}-NET-${Math.floor(1000 + Math.random() * 9000)}-2024`,
    subject: 'Mathematics (041)',
    center: `DEL-${Math.floor(1000 + Math.random() * 9000)}`,
    riskScore: 20
  };

  req.session.user = user;
  return res.status(200).json({ user });
});

// Log Out endpoint
router.post('/logout', (req, res) => {
  if (req.session && req.session.user) {
    req.session.destroy(err => {
      if (err) {
        return res.status(500).json({ error: 'Could not log out' });
      }
      res.clearCookie('evalsync_sid');
      return res.status(200).json({ message: 'Logged out successfully' });
    });
  } else {
    return res.status(200).json({ message: 'No active session to log out' });
  }
});

module.exports = router;
