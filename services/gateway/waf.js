// WAF & RASP Engine for API Gateway
// Aligns with OWASP Top 10 mitigation rules

const WAF_PATTERNS = {
  sqli: /(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|update\s+.*\s+set|'--|' \/\*|or\s+\d+\s*=\s*\d+|' or ''='|admin' --)/gi,
  xss: /(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|alert\(|document\.cookie|eval\(|window\.location)/gi,
  pathTraversal: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\/etc\/passwd|\/windows\/win\.ini|boot\.ini)/gi,
  cmdInjection: /(;\s*(rm|cat|ls|dir|wget|curl|whoami|id|sh|bash|powershell|cmd)|\|\s*(rm|cat|ls|dir|whoami|id)|`.*`|\$\(.*\))/gi,
  xxe: /(<!entity|<!doctype|xml\s+version)/gi
};

// Configurable rules
let wafEnabled = true;

// WAF Middleware
function wafMiddleware(req, res, next) {
  if (!wafEnabled) return next();

  const payloadSource = [
    { name: 'URL Query', data: JSON.stringify(req.query || {}) },
    { name: 'Request Body', data: typeof req.body === 'object' ? JSON.stringify(req.body || {}) : String(req.body || '') },
    { name: 'Headers', data: JSON.stringify(req.headers || {}) }
  ];

  for (const source of payloadSource) {
    if (!source.data || source.data === '{}') continue;

    for (const [attackType, regex] of Object.entries(WAF_PATTERNS)) {
      if (regex.test(source.data)) {
        const correlationId = req.headers['x-correlation-id'] || 'corr-' + Math.random().toString(36).substring(2, 9);
        const ip = req.ip || '127.0.0.1';

        // Normalized CEF Log Format for SIEM
        const cefMessage = `CEF:0|EvalSync|GatewayWAF|6.0|WAF-100|${attackType.toUpperCase()} Attack Blocked|8|src=${ip} request=${req.path} msg=Payload matched signature in ${source.name} cn1=${correlationId}`;
        console.warn(`[SIEM ALERT] ${cefMessage}`);

        // Register telemetry details via global control plane metrics if accessible
        if (global.registerBlockedAttack) {
          global.registerBlockedAttack(attackType, ip, req.path);
        }

        return res.status(403).json({
          error: 'Security Violation: Request blocked by WAF/RASP policies.',
          correlationId,
          code: 'WAF_BLOCKED'
        });
      }
    }
  }

  next();
}

// RASP Runtime Self-Protection function
function raspGuard(targetObject, propertyName, value) {
  // Guard against runtime injection or prototype pollution
  if (propertyName === '__proto__' || propertyName === 'constructor' || propertyName === 'prototype') {
    console.error(`[RASP BLOCK] Attempted Prototype Pollution on property: ${propertyName}`);
    throw new Error('Security Violation: Prototype pollution blocked.');
  }

  // Check strings for dangerous content
  if (typeof value === 'string') {
    for (const [attackType, regex] of Object.entries(WAF_PATTERNS)) {
      if (regex.test(value)) {
        console.error(`[RASP BLOCK] ${attackType.toUpperCase()} detected in memory write: ${propertyName} = "${value.substring(0, 40)}..."`);
        throw new Error(`Security Violation: Dangerous payload detected in memory.`);
      }
    }
  }

  return value;
}

module.exports = {
  wafMiddleware,
  raspGuard,
  setWafEnabled: (val) => { wafEnabled = !!val; }
};
