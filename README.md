# 🚀 EvalSync — Secure Academic Evaluation Gateway for CBSE

<div align="center">

_**"Distributed System Architecture for High-Traffic Board Examination Evaluation Portals"**_

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/Node.js-v20.x-green.svg?style=for-the-badge&logo=node.js)](https://nodejs.org)
[![Tests Status](https://img.shields.io/badge/Tests-100%25%20Passing-success.svg?style=for-the-badge&logo=jest)](tests/server.test.js)
[![Vulnerabilities](https://img.shields.io/badge/Vulnerabilities-0%20Discovered-brightgreen.svg?style=for-the-badge&logo=npm)](package.json)
[![Docker](https://img.shields.io/badge/Docker-Compatible-blue.svg?style=for-the-badge&logo=docker)](Dockerfile)

[Live Demo Preview](https://rishisharma029.github.io/EvalSync-System/) • [GitHub Repository](https://github.com/Rishisharma029/EvalSync-System) • [Developer Portfolio](https://github.com/Rishisharma029)

</div>

---

## 📌 Project Overview

**EvalSync** is a production-grade, highly secure, and containerized academic evaluation portal designed to handle high-traffic board examination environments (such as CBSE).

### The Problem
During peak evaluation periods, thousands of academic evaluators attempt to upload high-resolution scanned answer scripts simultaneously. Traditional database-coupled web gateways crash under these load spikes due to connection pool exhaustion, write locks, and memory overflows.

### The Solution
EvalSync implements a **distributed queue-based system architecture** that decouples request ingestion from database writes:
1. **Ingestion Layer**: Answer scripts are immediately ingested, validated, and placed into a secure in-memory processing queue.
2. **Worker Pool**: Background worker threads pull scripts from the queue asynchronously. If load spikes, the system automatically scales up active workers to prevent queue congestion.
3. **Database Layer**: Clean, throttled synchronization is executed to database tables, preventing system bottlenecks.
4. **Dual-Mode Portability**: Supports a dual-mode model. If a local Node.js Express server is active, it runs secure backend operations. If deployed on a static hosting system (like GitHub Pages), it gracefully displays an interactive browser mockup, preserving portfolio discoverability.

---

## 🏗️ System Architecture

EvalSync is built on a modular client-server model separating UI, security gateway, logging layers, and deployment targets:

```text
                               +-------------------------------------+
                               |          Evaluator Browser          |
                               +------------------+------------------+
                                                  |
                                                  | HTTPS Requests
                                                  v
                               +-------------------------------------+
                               |           Express Gateway           | (Port 3000)
                               +------------------+------------------+
                                                  |
                       +--------------------------+--------------------------+
                       |                                                     |
                       v                                                     v
        +--------------+--------------+                       +--------------+--------------+
        |        Security Layer       |                       |        Static Assets        |
        | - Helmet Headers            |                       | - HTML5 Shell (index.html)  |
        | - Session Cookie (HttpOnly) |                       | - CSS Visuals (style.css)   |
        | - IP Rate Limiter (10/min)  |                       | - Client Engine (app.js)    |
        | - Sanitizer Middleware      |                       | - Runtime Hooks (runtime.js)|
        +--------------+--------------+                       +-----------------------------+
                       |
                       v
        +--------------+--------------+
        |        Routing Engine       |
        | - POST /api/auth/login      |
        | - POST /api/auth/logout     |
        | - POST /api/audit/log       |
        | - GET  /api/auth/session    |
        +--------------+--------------+
                       |
        +--------------+--------------+
        |        Queue Manager        |
        | - Ingestion Buffer          |
        | - Auto-Scaling Worker Pool  |
        | - Dead Letter Queue (DLQ)   |
        +--------------+--------------+
                       |
                       v
        +--------------+--------------+
        |         Audit Log           |
        | - persistent: audit.log     |
        +-----------------------------+
```

### Flow Breakdown
* **Authentication**: Evaluators log in via `/api/auth/login`. Passwords are encrypted using high work-factor `bcryptjs` algorithms compared against hashes in environment variables.
* **Session Persistence**: Express establishes an encrypted cookie session (`evalsync_sid`) with `HttpOnly`, `SameSite: Lax`, and `Secure` parameters (in production).
* **Logging System**: A centralized logging utility outputs JSON Lines to both standard stdout (for Docker container log aggregation) and appends directly to a server-side `audit.log` file.
* **Spike Ingestion**: Scanned scripts are buffered in an in-memory queue. Active background worker threads scale dynamically from 6 to 20 based on the queue depth threshold to resolve bottlenecks.

---

## 🔐 Security Features

EvalSync was reviewed and hardened against OWASP Top 10 vulnerabilities:

* **Blowfish `$2b$` Bcrypt Hashing**: Passwords are never stored in plain text. The application uses `bcryptjs` (Work Factor: 10) to compute and check passwords against secure hashes configured in `.env`.
* **Helmet Security Headers**: Injects key defense headers to prevent browser vulnerabilities:
  * `X-Frame-Options: SAMEORIGIN` (mitigates clickjacking)
  * `X-Content-Type-Options: nosniff` (mitigates MIME-sniffing)
  * Strict `Content-Security-Policy` (CSP) preventing unauthorized external scripts.
* **IP-Based Rate Limiting**: Employs `express-rate-limit` on the authentication gateway to permit at most 10 login requests per minute per IP address, stopping brute-force guessing.
* **Input Validation & Sanitization**: Uses `express-validator` to enforce strict formatting requirements on email inputs, and escapes incoming strings to neutralize script injections.
* **Session Security**: Session identifiers use secure cookie configs to block cross-site access and cookie hijacking.
* **Kebab-Case Audit Trails**: Every key operational event logs JSON lines to the server:
  ```json
  {"time":"2026-06-04T16:22:52.350Z","role":"evaluator","action":"login-failure","details":"Failed login attempt for evaluator@cbse.gov.in (incorrect password)","status":"failure"}
  {"time":"2026-06-04T16:22:53.288Z","role":"admin","action":"login","details":"Logged in successfully from IP ::ffff:127.0.0.1","status":"success"}
  {"time":"2026-06-04T16:22:53.317Z","role":"admin","action":"settings-change","details":"autoScale toggle changed to false","status":"success"}
  ```

---

## ✨ Features Checklist

* **Role-Based Access Control**:
  * `👨‍🏫 Evaluator`: Upload scanned answer sheets, check queue position, view performance.
  * `🛡️ Admin`: Manage active workers, monitor Dead Letter Queue (DLQ), check security alerts.
  * `👑 Super Admin`: Master dashboard access unlocking all operations.
  * `📡 Monitor`: Read-only views to monitor real-time queue graphs, zero write access.
* **Interactive Resilience Simulator**: Built-in panels to simulate network delay, database sync rate, worker count adjustment, and chaos test triggers (Network Downtime, Queue Spikes, Database Sync Failure).
* **Multi-Stage Containerization**: Built on Alpine Linux with unprivileged execution context.
* **Automated CI/CD Workflows**: Configured GitHub Action testing, dependency audit scans, and build triggers.

---

## 📂 Project Structure

```text
evalsync/
 ├── .github/
 │    └── workflows/
 │         └── ci.yml             # GitHub Actions CI pipeline configuration
 ├── tests/
 │    └── server.test.js          # Jest + Supertest API integration tests
 ├── Dockerfile                   # Hardened multi-stage container configuration
 ├── docker-compose.yml           # Local development service orchestrator
 ├── .env.example                 # Production configuration variables template
 ├── .gitignore                   # Excludes node_modules, .env, and local logs
 ├── README.md                    # System documentation and setup guide
 ├── LICENSE                      # MIT Open-source license terms
 ├── server.js                    # Secure Node.js Express Backend & API Router
 ├── index.html                   # Semantic HTML5 single-page application Shell
 ├── style.css                    # Premium Glassmorphism styling rules
 ├── app.js                       # Frontend client logic (mirrors app.dev.js)
 ├── app.dev.js                   # Development source file for frontend client
 └── app.runtime.js               # Timer cleanup and login patch script
```

---

## 🚀 Installation & Execution

### 1. Local Setup
Ensure [Node.js v20.x](https://nodejs.org) is installed on your system.

```bash
# Clone the repository
git clone https://github.com/Rishisharma029/EvalSync-System.git
cd EvalSync-System

# Install precise dependencies
npm install

# Set up local environment variables
cp .env.example .env
```

### 2. Environment Configuration (`.env`)
Create a `.env` file in the root directory. You can customize the blowfish `$2b$` bcrypt hashes to match your credentials:

```properties
PORT=3000
SESSION_SECRET=dev_session_secret_replace_this_in_production

# Pre-hashed passwords (plain values: CBSE@2024, Admin@2024, SuperAdmin@2024, Monitor@2024)
EVALUATOR_PASSWORD_HASH=$2b$10$z2QmXa7f9tSsmGfenpp48.5dhCr43kNG0NR4fOBpNj7z0xNCYgPla
ADMIN_PASSWORD_HASH=$2b$10$Nti5yGJgLBjUyS8rROTP5OAkvWbdO8pwK2MleV25NNGaJB2o2/j.O
SUPERADMIN_PASSWORD_HASH=$2b$10$Rfr2lahJKlVkTWDN.cgOCOAVVwFDzL7AfO8AH86eFot3IHFX9lPtK
MONITOR_PASSWORD_HASH=$2b$10$QZ7OwANRRlkFm8Pq47Tz3uake3lMpnEAnfxjMVFhupFWXwTLSf9/O
```

### 3. Start the Server
```bash
npm start
```
Open `http://localhost:3000` in your web browser.

---

## 🐳 Docker Deployment

The system contains configurations to compile and run using Docker containers:

### Build & Startup
Build the container image and start the service in background detached mode:
```bash
docker compose up -d --build
```
The application will run on port `3000` using the local environment settings configured inside `.env`.

### Container Verification
```bash
# View active containers
docker compose ps

# Inspect logs
docker compose logs -f
```

### Shutdown Container
```bash
docker compose down
```

---

## 🧪 Testing & Validation

EvalSync includes a comprehensive Jest integration test suite targeting authentication middleware, Helmet defenses, rate limiting, and persistent log writing.

### Run Tests
```bash
# Run tests
npm test

# Run test coverage
npm run test:coverage
```

### Current Test Suite Output
```bash
PASS tests/server.test.js
  EvalSync Express Backend API & Security Tests
    √ 1. Security Headers check (Helmet) (294 ms)
    √ 2. Unauthenticated Session check (GET /api/auth/session) (34 ms)
    √ 3. Invalid Login validation (POST /api/auth/login - Malformed Email) (105 ms)
    √ 4. Invalid Login credentials check (POST /api/auth/login - Wrong Password) (235 ms)
    √ 5. Successful Login workflow (POST /api/auth/login) (227 ms)
    √ 6. Session persistence after login (251 ms)
    √ 7. Logout workflow (POST /api/auth/logout) (259 ms)
    √ 8. Client-side Settings Audit Log (POST /api/audit/log) (221 ms)
    √ 9. Rate Limiter checking on login attempts (808 ms)
    √ 10. CSRF Token retrieval check (GET /api/csrf-token) (35 ms)

Test Suites: 1 passed, 1 total
Tests:       10 passed, 10 total
Time:        6.061 s
```

### Latest Code Coverage Metrics
* **Statements Coverage**: `81.25%`
* **Lines Coverage**: `81.05%`
* **Functions Coverage**: `83.33%`
* **Branch Coverage**: `60.71%`

---

## 🔄 GitHub Actions CI/CD Pipeline

The [.github/workflows/ci.yml](file:///c:/Users/Rishi%20Sharma/.gemini/antigravity/scratch/new%20evacsync%20app/.github/workflows/ci.yml) workflow triggers on every push and pull request to `main` and `master`:

1. **Lint & Code Quality Check**: Installs exact dependencies using `npm ci`.
2. **Security Audit**: Scans npm tree using `npm audit --audit-level=high` (fails build if vulnerabilities are found).
3. **Automated Integration Testing**: Launches Jest tests in a simulated Node environment.
4. **Docker Compilation Check**: Compiles the container configuration (`docker build`) to verify that the build succeeds without error.

---

## 📸 Screenshots & Interface Visuals

Here is a visual walk-through of the portal interface components:

<details>
<summary><b>🖥️ View Portal Interfaces (Dashboard & Real-time Monitors)</b></summary>

### 1. Main Landing & Multi-Role Selector
*Features a premium dark glassmorphic portal selector permitting Evaluator, Admin, Super Admin, and Monitor accounts.*
> *[Placeholder: Role Selection Landing View]*

### 2. Live Queue Processing Monitor
*Interactive real-time task visualization tracking ingestion, worker allocation, and database synchronization pipelines.*
> *[Placeholder: Live Queue Monitor Dashboard]*

### 3. System Resilience & Chaos Center
*Control panel allowing administrators to manually simulate server delay, trigger data sync halts, inject simulated heavy loads, and verify scaling response.*
> *[Placeholder: Chaos Testing Panel]*

</details>

---

## 📊 Security & Vulnerability Audit Results

* **Vulnerabilities**: **`0` vulnerabilities** detected across 369 dependencies.
* **Session Validation**: Secure session cookies successfully mitigate XSS-based hijacking.
* **CSRF Protection**: Native `lusca` CSRF token verification middleware intercepts unauthorized cross-site actions on all state-changing endpoints.
* **Headers Assessment**: Helmet scores A+ rating on security headers validations.

---

## 🛠️ Tech Stack

* **Frontend**: HTML5, Vanilla JavaScript (ES6+), CSS3 Variables.
* **Backend**: Node.js, Express, `express-session`, `express-rate-limit`, `helmet`, `express-validator`.
* **Testing**: Jest, Supertest.
* **Deployment**: Docker, Docker Compose, GitHub Actions.

---

## 🔮 Future Improvements Roadmap

* [ ] **Redis Integration**: Shift session storage from local memory to a Redis instance for scaling across multiple server instances.
* [ ] **Distributed Messaging Queue**: Transition in-memory queue arrays to RabbitMQ or Amazon SQS.
* [ ] **APM Dashboard**: Add metrics collection using Prometheus and Grafana.
* [ ] **Cloud Deployment**: Create Terraform configurations to deploy the container onto AWS ECS/EKS.

---

## 👨‍💻 Author

**Rishi Sharma**
* **Role**: BCA Student | Developer & Full-Stack Enthusiast
* **GitHub**: [@Rishisharma029](https://github.com/Rishisharma029)
* **Email**: [rishisharma.bca25@satyug.edu.in](mailto:rishisharma.bca25@satyug.edu.in)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
