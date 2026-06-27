const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

const router = express.Router();

const ROLES_INFO = {
  evaluator: { email: 'evaluator@cbse.gov.in', name: 'Rajan Mehta', initials: 'RM', label: '👨‍🏫 Evaluator', description: 'Upload answer scripts & track your queue position' },
  admin: { email: 'admin@cbse.gov.in', name: 'Priya Singh', initials: 'PS', label: '🛡️ Admin', description: 'Queue control, DLQ recovery, DB sync & security audit' },
  superadmin: { email: 'superadmin@cbse.gov.in', name: 'Dr. Arvind Kumar', initials: 'AK', label: '👑 Super Admin', description: 'Full system access — all modules unlocked' },
  monitor: { email: 'monitor@cbse.gov.in', name: 'Sanjay Patel', initials: 'SP', label: '📡 Monitor', description: 'Read-only monitoring — all views, zero write access' }
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
    default:
      return null;
  }
};

// Verify current session
router.get('/session', (req, res) => {
  if (req.session && req.session.user) {
    return res.status(200).json({ user: req.session.user });
  }
  return res.status(401).json({ error: 'No active session' });
});

// Log In endpoint with validation and sanitization
router.post(
  '/login',
  [
    body('email').trim().isEmail().normalizeEmail().withMessage('A valid email address is required'),
    body('password').trim().notEmpty().withMessage('Password is required')
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { email, password } = req.body;

    // Identify which role matches this email
    const matchedRoleKey = Object.keys(ROLES_INFO).find(key => ROLES_INFO[key].email === email);

    if (!matchedRoleKey) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify hashed password using bcrypt
    const hash = getRolePasswordHash(matchedRoleKey);
    const isMatch = hash && bcrypt.compareSync(password, hash);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
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
      center: `DEL-${Math.floor(1000 + Math.random() * 9000)}`
    };

    req.session.user = user;
    return res.status(200).json({ user });
  }
);

// Log Out endpoint
router.post('/logout', (req, res) => {
  if (req.session && req.session.user) {
    const email = req.session.user.email;
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
