const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const lusca = require('lusca');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Setup static user data
const ROLES_INFO = {
  evaluator: { email: 'evaluator@cbse.gov.in', name: 'Rajan Mehta', initials: 'RM', label: '👨‍🏫 Evaluator', description: 'Upload answer scripts & track your queue position' },
  admin: { email: 'admin@cbse.gov.in', name: 'Priya Singh', initials: 'PS', label: '🛡️ Admin', description: 'Queue control, DLQ recovery, DB sync & security audit' },
  superadmin: { email: 'superadmin@cbse.gov.in', name: 'Dr. Arvind Kumar', initials: 'AK', label: '👑 Super Admin', description: 'Full system access — all modules unlocked' },
  monitor: { email: 'monitor@cbse.gov.in', name: 'Sanjay Patel', initials: 'SP', label: '📡 Monitor', description: 'Read-only monitoring — all views, zero write access' }
};

// Secure password hashes loaded from environment variables.
// Fallbacks are the standard CBSE passwords pre-hashed (e.g. CBSE@2024, Admin@2024, etc.).
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

// 2. Audit Logging Utility
function writeAuditLog(role, action, details, status = 'success') {
  const logEntry = {
    time: new Date().toISOString(),
    role: role || 'anonymous',
    action,
    details: details || '',
    status
  };
  
  // Console output (useful for docker logs)
  console.log(`[AUDIT] ${JSON.stringify(logEntry)}`);
  
  // Write to persistent audit.log file (JSON Lines format)
  const logFilePath = path.join(__dirname, 'audit.log');
  fs.appendFile(logFilePath, JSON.stringify(logEntry) + '\n', (err) => {
    if (err) {
      console.error('[AUDIT ERROR] Failed to write to audit.log', err);
    }
  });
}

// 1. Security Hardening: Security Headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false
}));

// 1. Security Hardening: Global Rate Limiting for all routes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 requests per 15 minutes
  message: { error: 'Too many requests from this IP. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1. Security Hardening: Secure Session Handling
const isProd = process.env.NODE_ENV === 'production';
app.use(session({
  name: 'evalsync_sid',
  secret: process.env.SESSION_SECRET || 'dev_session_secret_replace_this_in_production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000 // 30 minutes
  }
}));

// 1. Security Hardening: CSRF Protection
// Active in all environments except testing
if (process.env.NODE_ENV !== 'test') {
  app.use(lusca.csrf());
}

// 1. Security Hardening: Rate Limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10,
  message: { error: 'Too many authentication attempts. Please try again after 60 seconds.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/auth/login', authLimiter);

// --- API Endpoints ---

// CSRF Token endpoint for Single Page Application client integration
app.get('/api/csrf-token', (req, res) => {
  return res.status(200).json({ csrfToken: res.locals._csrf || '' });
});

// Verify current session
app.get('/api/auth/session', (req, res) => {
  if (req.session && req.session.user) {
    return res.status(200).json({ user: req.session.user });
  }
  return res.status(401).json({ error: 'No active session' });
});

// Log In endpoint with validation and sanitization
app.post(
  '/api/auth/login',
  [
    body('email').trim().isEmail().normalizeEmail().withMessage('A valid email address is required'),
    body('password').trim().notEmpty().withMessage('Password is required')
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      writeAuditLog('anonymous', 'login-failure', `Input validation failed: ${errors.array()[0].msg}`, 'failure');
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { email, password } = req.body;

    // Identify which role matches this email
    const matchedRoleKey = Object.keys(ROLES_INFO).find(key => ROLES_INFO[key].email === email);

    if (!matchedRoleKey) {
      writeAuditLog('anonymous', 'login-failure', `Failed login attempt for unknown email: ${email}`, 'failure');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify hashed password using bcrypt from env
    const hash = getRolePasswordHash(matchedRoleKey);
    const isMatch = hash && bcrypt.compareSync(password, hash);

    if (!isMatch) {
      writeAuditLog(matchedRoleKey, 'login-failure', `Failed login attempt for ${email} (incorrect password)`, 'failure');
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
    writeAuditLog(matchedRoleKey, 'login', `Logged in successfully from IP ${req.ip}`, 'success');
    return res.status(200).json({ user });
  }
);

// Log Out endpoint
app.post('/api/auth/logout', (req, res) => {
  if (req.session && req.session.user) {
    const roleKey = req.session.user.roleKey;
    const email = req.session.user.email;
    req.session.destroy(err => {
      if (err) {
        writeAuditLog(roleKey, 'logout', `Failed to clear session for ${email}`, 'failure');
        return res.status(500).json({ error: 'Could not log out' });
      }
      res.clearCookie('evalsync_sid');
      writeAuditLog(roleKey, 'logout', `Logged out successfully for ${email}`, 'success');
      return res.status(200).json({ message: 'Logged out successfully' });
    });
  } else {
    return res.status(200).json({ message: 'No active session to log out' });
  }
});

// Endpoint to allow client-side actions to append to audit logs (like setting changes or chaos tests)
app.post(
  '/api/audit/log',
  [
    body('action').trim().notEmpty().withMessage('Action is required'),
    body('details').trim().escape()
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const roleKey = req.session && req.session.user ? req.session.user.roleKey : 'anonymous';
    const { action, details } = req.body;

    writeAuditLog(roleKey, action, details, 'success');
    return res.status(200).json({ success: true });
  }
);

// Serve frontend static assets from current directory
app.use(express.static(path.join(__dirname)));

// Wildcard fallback to index.html for single page app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start listening if run directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🔒 EvalSync Secure Production Server Running`);
    console.log(`🚀 Port: ${PORT}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`====================================================`);
    writeAuditLog('system', 'startup', `Server started listening on port ${PORT}`);
  });
}

module.exports = app;
