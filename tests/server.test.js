const request = require('supertest');
const app = require('../server');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

describe('EvalSync Express Backend API & Security Tests', () => {
  
  test('1. Security Headers check (Helmet)', async () => {
    const response = await request(app).get('/');
    
    // Verify common security headers set by helmet
    expect(response.headers['x-frame-options']).toMatch(/DENY|SAMEORIGIN/);
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['x-download-options']).toBe('noopen');
    expect(response.headers['x-permitted-cross-domain-policies']).toBe('none');
  });

  test('2. Unauthenticated Session check (GET /api/auth/session)', async () => {
    const response = await request(app).get('/api/auth/session');
    
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: 'No active session' });
  });

  test('3. Invalid Login validation (POST /api/auth/login - Malformed Email)', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({ email: 'not-an-email', password: 'some_password' });

    expect(response.status).toBe(400);
    expect(response.body.error).toContain('valid email address');
  });

  test('4. Invalid Login credentials check (POST /api/auth/login - Wrong Password)', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({ email: 'evaluator@cbse.gov.in', password: 'wrongpassword' });

    expect(response.status).toBe(401);
    expect(response.body.error).toBe('Invalid credentials');
  });

  test('5. Successful Login workflow (POST /api/auth/login)', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({ email: 'evaluator@cbse.gov.in', password: 'CBSE@2024' });

    expect(response.status).toBe(200);
    expect(response.body.user).toBeDefined();
    expect(response.body.user.email).toBe('evaluator@cbse.gov.in');
    expect(response.body.user.role).toBe('👨‍🏫 Evaluator');
    expect(response.body.user.roleKey).toBe('evaluator');
    expect(response.headers['set-cookie']).toBeDefined(); // Session cookie should be set
  });

  test('6. Session persistence after login', async () => {
    const agent = request.agent(app);
    
    // Login
    await agent
      .post('/api/auth/login')
      .send({ email: 'admin@cbse.gov.in', password: 'Admin@2024' });
      
    // Fetch session using same agent
    const sessionResponse = await agent.get('/api/auth/session');
    
    expect(sessionResponse.status).toBe(200);
    expect(sessionResponse.body.user.email).toBe('admin@cbse.gov.in');
    expect(sessionResponse.body.user.roleKey).toBe('admin');
  });

  test('7. Logout workflow (POST /api/auth/logout)', async () => {
    const agent = request.agent(app);
    
    // Login
    await agent
      .post('/api/auth/login')
      .send({ email: 'superadmin@cbse.gov.in', password: 'SuperAdmin@2024' });
      
    // Logout
    const logoutResponse = await agent.post('/api/auth/logout');
    expect(logoutResponse.status).toBe(200);
    expect(logoutResponse.body.message).toBe('Logged out successfully');
    
    // Verify session is indeed cleared
    const sessionResponse = await agent.get('/api/auth/session');
    expect(sessionResponse.status).toBe(401);
  });

  test('8. Client-side Settings Audit Log (POST /api/audit/log)', async () => {
    const agent = request.agent(app);
    
    // Login to get a role
    await agent
      .post('/api/auth/login')
      .send({ email: 'admin@cbse.gov.in', password: 'Admin@2024' });

    // Send a settings change event
    const auditResponse = await agent
      .post('/api/audit/log')
      .send({ action: 'settings-change', details: 'autoScale toggle changed to false' });

    expect(auditResponse.status).toBe(200);
    expect(auditResponse.body.success).toBe(true);

    // Verify it appended to audit.log
    const logFilePath = path.join(__dirname, '../audit.log');
    expect(fs.existsSync(logFilePath)).toBe(true);
    const logs = fs.readFileSync(logFilePath, 'utf8');
    expect(logs).toContain('"action":"settings-change"');
    expect(logs).toContain('"role":"admin"');
    expect(logs).toContain('autoScale toggle changed to false');
  });

  test('9. Rate Limiter checking on login attempts', async () => {
    // Note: The rate limiter allows max 10 requests per minute.
    // We will make requests in a loop until we hit a 429.
    let hit429 = false;
    for (let i = 0; i < 15; i++) {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'evaluator@cbse.gov.in', password: 'CBSE@2024' });
      
      if (res.status === 429) {
        hit429 = true;
        expect(res.body.error).toContain('Too many authentication attempts');
        break;
      } else {
        expect(res.status).toBe(200);
      }
    }
    expect(hit429).toBe(true);
  });

  test('10. CSRF Token retrieval check (GET /api/csrf-token)', async () => {
    const response = await request(app).get('/api/csrf-token');
    expect(response.status).toBe(200);
    expect(response.body.csrfToken).toBeDefined();
  });
});
