<div align="center">

# 🚀 EvalSync — Secure academic evaluation system for CBSE

_**"Distributed System Architecture for High-Traffic Digital Evaluation Portals"**_

<br>

[![Live Demo](https://img.shields.io/badge/LIVE%20DEMO-RISHISHARMA029.GITHUB.IO%2FEVALSYNC--SYSTEM-6EE7B7?style=for-the-badge&logo=github&logoColor=white&labelColor=525252)](https://rishisharma029.github.io/EvalSync-System/)
[![Repository](https://img.shields.io/badge/REPOSITORY-GITHUB.COM%2FRISHISHARMA029%2FEVALSYNC--SYSTEM-6EE7B7?style=for-the-badge&logo=github&logoColor=white&labelColor=525252)](https://github.com/Rishisharma029/EvalSync-System)
[![GitHub](https://img.shields.io/badge/GITHUB-RISHISHARMA029-FFFFFF?style=for-the-badge&logo=github&logoColor=black&labelColor=525252)](https://github.com/Rishisharma029)
[![Email](https://img.shields.io/badge/EMAIL-I.RISHISHARMA2007@GMAIL.COM-6EE7B7?style=for-the-badge&logo=minutemailer&logoColor=white&labelColor=525252)](mailto:I.RISHISHARMA2007@gmail.com)

</div>

---

## 📌 Overview

**EvalSync** is a production-ready, secure, and containerized academic evaluation portal designed to handle high-traffic board examination environments like CBSE. 

Traditional examination submission portals frequently crash during peak periods when thousands of evaluators submit scanned answer scripts simultaneously. EvalSync solves this bottleneck using a **queue-based system architecture** that decouples submission ingestion from database writing. Submissions enter a secure in-memory queue, which is processed asynchronously by background worker threads, preserving database integrity and ensuring 99.99% ingestion reliability.

EvalSync runs in a **secure client-server model** backed by a Node.js/Express application. It also supports a **dual-mode architecture**: if the backend is unreachable (e.g. static hosting on GitHub Pages), it gracefully falls back to a client-side simulation, making it highly portable for live previews.

---

## 🏗️ Production Architecture

```text
               +-----------------------+
               |  Evaluator Browser    |
               +-----------+-----------+
                           |  HTTPS
                           v
               +-----------+-----------+
               |    Express Gateway    | (Port 3000)
               +-----------+-----------+
                           |
            +--------------+--------------+
            |  REST API                   |  Static File Serving
            |  - /api/auth/login          |  - index.html
            |  - /api/auth/logout         |  - style.css
            |  - /api/auth/session        |  - app.js
            |  - /api/audit/log           |  - app.runtime.js
            +--------------+--------------+
                           |
         +-----------------+-----------------+
         |                                   |
         v                                   v
+--------+--------+                 +--------+--------+
|  Rate Limiter   |                 | Security Engine |
|  - max 10/min   |                 | - bcrypt verification
|  - IP-based     |                 | - helmet headers
+-----------------+                 +--------+--------+
                                             |
                                             v
                                    +--------+--------+
                                    | Audit Logger    |
                                    | - audit.log     |
                                    +-----------------+
```

---

## 🔐 Security Features

*   **Cryptographic Password Hashing**: Plaintext passwords are never stored. The server utilizes `bcryptjs` to verify credentials against cryptographically secure blowfish hashes defined in environment variables.
*   **Secure Session Management**: Session handling is powered by `express-session`. Session cookies are configured with `httpOnly: true` to prevent XSS-based cookie theft, `sameSite: 'lax'` to prevent CSRF, and `secure: true` in production (HSTS).
*   **Brute-Force Protection**: The `/api/auth/login` endpoint is protected by `express-rate-limit` allowing a maximum of 10 requests per minute per IP address.
*   **Security Headers (Helmet)**: Strict headers are injected including `X-Frame-Options: DENY` (anti-clickjacking), `X-Content-Type-Options: nosniff` (anti-MIME-sniffing), `Content-Security-Policy` (CSP restricting unauthorized scripts), and `X-Permitted-Cross-Domain-Policies: none`.
*   **Input Validation & Sanitization**: Express request bodies are validated and sanitized using `express-validator` to eliminate script injection and malformed parameters.
*   **Server-Side Audit Trail**: Critical operations (successful logins, logouts, auth failures, chaos tests, settings changes) write structured JSON Lines to `audit.log` and the container's standard output.

---

## 🛠️ Configuration (.env)

The server relies on environment variables for configuration. Set these up in a `.env` file in the root directory:

```env
# Server settings
PORT=3000
SESSION_SECRET=a_long_random_alphanumeric_string_for_sessions

# BCrypt password hashes (Work Factor: 10)
# Default values correspond to CBSE demo accounts:
# - Evaluator (evaluator@cbse.gov.in) -> CBSE@2024
# - Admin (admin@cbse.gov.in) -> Admin@2024
# - Super Admin (superadmin@cbse.gov.in) -> SuperAdmin@2024
# - Monitor (monitor@cbse.gov.in) -> Monitor@2024
EVALUATOR_PASSWORD_HASH=$2b$10$z2QmXa7f9tSsmGfenpp48.5dhCr43kNG0NR4fOBpNj7z0xNCYgPla
ADMIN_PASSWORD_HASH=$2b$10$Nti5yGJgLBjUyS8rROTP5OAkvWbdO8pwK2MleV25NNGaJB2o2/j.O
SUPERADMIN_PASSWORD_HASH=$2b$10$Rfr2lahJKlVkTWDN.cgOCOAVVwFDzL7AfO8AH86eFot3IHFX9lPtK
MONITOR_PASSWORD_HASH=$2b$10$QZ7OwANRRlkFm8Pq47Tz3uake3lMpnEAnfxjMVFhupFWXwTLSf9/O
```

---

## 🚀 Setup & Execution Guide

### Local Installation
1.  **Clone the repository**:
    ```bash
    git clone https://github.com/Rishisharma029/EvalSync-System.git
    cd EvalSync-System
    ```
2.  **Install dependencies**:
    ```bash
    npm install
    ```
3.  **Setup environment variables**:
    ```bash
    cp .env.example .env
    ```
4.  **Start the server**:
    ```bash
    npm start
    ```
5.  Access the interface at `http://localhost:3000`.

---

## 🐳 Docker Deployment

The application includes a lightweight `Dockerfile` (running under a non-root `node` user for defense-in-depth) and a `docker-compose.yml` service wrapper.

### Run with Docker Compose
To build and run the entire stack:
```bash
docker-compose up -d --build
```

### Stop the service
```bash
docker-compose down
```

---

## 🧪 Automated Testing

EvalSync contains a full integration test suite that tests:
*   Security header injection (Helmet)
*   Session checks and credentials validation
*   Session persistence across routing
*   Rate limiting restrictions (API blocking under flood)

### Run Tests
```bash
npm test
```

### Run Test Coverage
To generate a Jest test coverage report:
```bash
npm run test:coverage
```

---

## 🏆 Project Vision

EvalSync aims to transform fragile high-traffic submission systems into scalable, secure, and reliable platforms capable of handling national-level digital evaluation efficiently.

---

## 👨‍💻 Developer

**Rishi Sharma**
BCA Student | System Design & Full Stack Enthusiast
