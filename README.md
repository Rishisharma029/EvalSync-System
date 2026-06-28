# 🚀 EvalSync Enterprise Security 6.0 — Secure Academic Evaluation Gateway for CBSE

<div align="center">

_**"Distributed Microservices System Architecture, Zero-Trust Cryptographic Ledger, & Interactive Red Team Attack Simulator for High-Traffic Board Examination Evaluation Portals"**_

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/Node.js-v20.x-green.svg?style=for-the-badge&logo=node.js)](https://nodejs.org)
[![Tests Status](https://img.shields.io/badge/Tests-100%25%20Passing-success.svg?style=for-the-badge&logo=jest)](tests/server.test.js)
[![Vulnerabilities](https://img.shields.io/badge/Vulnerabilities-0%20Discovered-brightgreen.svg?style=for-the-badge&logo=npm)](package.json)
[![Docker](https://img.shields.io/badge/Docker-Compatible-blue.svg?style=for-the-badge&logo=docker)](Dockerfile)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ingress%20%26%20HPA-blue?style=for-the-badge&logo=kubernetes)](k8s/deployment.yaml)

[Live Demo Preview](https://rishisharma029.github.io/EvalSync-System/) • [GitHub Repository](https://github.com/Rishisharma029/EvalSync-System) • [Developer Portfolio](https://github.com/Rishisharma029)

</div>

---

## 📌 Project Overview & Purpose

**EvalSync Enterprise 6.0** is an industry-grade, highly secure, and containerized academic evaluation portal built specifically for CBSE (Central Board of Secondary Education, India) to manage the secure synchronization of answer scripts nationwide.

### The Nationwide Scalability Challenge
During peak board examination evaluation cycles, tens of thousands of evaluators across thousands of cities attempt to upload scanned, high-resolution answer scripts simultaneously. Traditional database-coupled applications fall victim to:
*   **Write locks and race conditions** on databases when handling bulk script updates.
*   **Connection pool exhaustion** as incoming HTTP threads wait for slow storage uploads.
*   **Severe memory overflows** under heavy traffic surges.

### The EvalSync Solution
EvalSync implements a **decoupled distributed queue architecture** combined with a **Zero-Trust Security Framework** to safely process high-traffic ingestions while locking down sensitive student record databases against unauthorized access, database scraping, and insider collusions.

---

## 🏗️ Core System Architecture

EvalSync is built to run in two separate modes:
*   **Monolithic In-Process Mode:** Fits perfectly in Jest test suites and lightweight local development.
*   **Distributed Microservices Mode:** Deploys as 11 decoupled microservices communicating through mTLS, utilizing Redis caching and RabbitMQ messaging, orchestrated via Kubernetes.

### 🌐 Distributed Microservices Diagram

```mermaid
graph TD
    User([Evaluator Client Browser]) -->|HTTPS / WAF / RASP| Gateway[API Gateway - Port 3000]
    
    subgraph Security Boundary [Zero-Trust Boundary]
        Gateway -->|mTLS / Route Proxies| AuthSvc[Auth Service]
        Gateway -->|mTLS / Route Proxies| SubSvc[Submission Service]
        Gateway -->|mTLS / Route Proxies| ControlPlane[Control Plane]
        
        AuthSvc -->|Evaluates IP, Geolocation, Device| RiskEngine[Adaptive Risk Engine]
        
        SubSvc -->|Generate Keys & Verify Integrity| HSM[FIPS 140-2 HSM Simulator]
        SubSvc -->|S3 Envelope Upload| ObjectStorage[(AWS S3 / MinIO Storage)]
        SubSvc -->|Upload Metadata| DBConn[(Primary Database - Mumbai)]
        
        Gateway -->|Event Stream| QueueSvc[Queue Service]
        QueueSvc -->|AMQP Pub/Sub| MsgQueue[[RabbitMQ Queue]]
        
        MsgQueue -->|Asynchronous Worker Pull| WorkerPool{Auto-Scaling Worker Pool}
        WorkerPool -->|Process Uploads & Write Metadata| DBConn
        
        WorkerPool -->|Dead Letter Queue| DLQSvc[DLQ Service]
        
        ControlPlane -->|Write Block Ledger| LedgerSvc[Cryptographic Ledger Svc]
        LedgerSvc -->|Chained SHA-256 Digest| LedgerFile[(Immutable Ledger File)]
    end

    DBConn -->|Replication Stream| DBReplica1[(Delhi Replica)]
    DBConn -->|Replication Stream| DBReplica2[(Chennai Replica)]
    DBConn -->|Replication Stream| DBReplica3[(Bangalore Replica)]
```

---

## 📁 Architectural Microservice Breakdown

All backend logic resides in the `services/` directory, split into 11 specialized layers:

### 1. API Gateway (`services/api-gateway/`)
*   **Reverse Proxy & Routing:** Forwards client traffic to target microservices.
*   **Circuit Breaker:** Prevents cascading system failures by tripping routes if backend errors spike.
*   **Response Caching & Request Compression:** Utilizes Gzip compression and caches static telemetry to optimize bandwidth.

### 2. Authentication Service (`services/auth-service/`)
*   **8 Role RBAC:** Enforces strict role boundaries mapping **Super Admin, Admin, Regional Admin, Moderator, Evaluator, Monitor, Auditor, and API Client** credentials.
*   **Adaptive Risk Engine:** Computes a risk score (0-100) on each login attempt evaluating:
    *   **Impossible Travel Speed:** Assesses geographic distances between successive logins.
    *   **Browser Fingerprint Shifts:** Flags anomalous User-Agents, screen resolutions, and OS headers.
*   **Brute-Force Progressive Lockout:** Enforces 15-minute lockouts after 5 consecutive failures, applying exponential response delays.

### 3. Submission Service (`services/submission-service/`)
*   **Integrity Verification:** Scrapes script uploads for malformed sizes, empty files, or structural injection code.
*   **Simulated FIPS 140-2 HSM Envelope Hashing:** Digitally signs uploads to ensure non-repudiation.
*   **Data Loss Prevention (DLP):** Blocks database scraping by capping evaluator downloads to a maximum of 5 script PDFs per session.
*   **Signed URL Generation:** Protects script files via temporary, 60-second expiring download URLs.

### 4. Audit & Ledger Service (`services/audit-service/`)
*   **Immutable Cryptographic Ledger:** Chains every system alteration, settings change, and blocked threat event.
*   **SHA-256 Digest Verification:** Blocks are chained using `SHA-256(Index | Timestamp | Role | Action | Details | Status | PreviousHash)`. Any unauthorized manual modifications to the log immediately break the hash chain and raise alert notifications.

### 5. Control Plane (`services/control-plane/`)
*   **Disaster Recovery (DR) Console:** Manages manual region failover procedures (Mumbai Primary -> Delhi Replica).
*   **Feature Flag Management:** Toggles features dynamically (such as prediction engine availability or auto-scaling rules) without code redeployment.
*   **AI Ops Chatbot Console (`/api/v1/control/chat`):** Chat agent parsing regional latencies and predicting tomorrow's traffic loads.
*   **Attack Simulator Console (`/api/v1/control/simulate-attack`):** Let admins trigger simulated SQLi, XSS, CSRF, JWT, Brute force, and DLP attacks to verify WAF/RASP blocks.

### 6. Queue Service (`services/queue-service/`)
*   Manages ingestion arrays and coordinates background payload buffering.

### 7. Worker Service (`services/worker-service/`)
*   Monitors queue depth and coordinates auto-scaling rules, spawning background worker threads from 6 up to 20 under heavy traffic.

### 8. DB Service (`services/db-service/`)
*   Coordinates central primary database operations and manages replica replication health metrics.

### 9. Analytics Service (`services/analytics-service/`)
*   Aggregates transaction throughput rates and measures network region latency.

### 10. Prediction Service (`services/prediction-service/`)
*   Houses AI regression models predicting tomorrow's script load based on active evaluator schedules.

### 11. Monitoring Service (`services/monitoring-service/`)
*   Monitors health check endpoints for each service card in the UI.

---

## 🛡️ Zero-Trust Security Gateway Controls

EvalSync contains early WAF/RASP request scanning filters implemented inside `services/gateway/waf.js`:

*   **SQL Injection (SQLi) Protection:** Regex scanner blocking patterns matching `' OR 1=1`, query unions (`UNION SELECT`), and database comments (`' --`).
*   **Cross-Site Scripting (XSS) Protection:** Neutralizes HTML script tags (`<script>`), event handlers (`onerror=`, `onclick=`), and eval code.
*   **Path Traversal Protection:** Rejects paths containing relative indicators (`../` or `..\`) and core configuration directories (`/etc/passwd`, `/windows/win.ini`).
*   **SIEM Logging:** Blocked events are parsed into a standardized Common Event Format (CEF) log:
    ```text
    CEF:0|CBSE|EvalSync|6.0|WAF_BLOCK|SQLi Attempt Blocked|8|src=192.168.1.114 act=blocked msg=SQL Injection pattern detected in parameter
    ```

---

## 🔬 Red Team Attack Simulation & SOC Console

EvalSync features an interactive **Executive SOC Dashboard** and an integrated **Red Team Simulation Center** in `index.html`:

```text
               [EXPLOT SIMULATION TRIGGERED]
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │  WAF/RASP Gateway Parsing Filter      │
        └───────────────────┬───────────────────┘
                            ├────────────────────────┐
                 [Matches Block Rules]     [No Violations]
                            │                        │
                            ▼                        ▼
        ┌───────────────────────────────────────┐   ┌─────────────────┐
        │ 🚨 Exploit Blocked, 403 Forbidden     │   │ Process Request │
        │ - Generate CEF alert payload          │   └─────────────────┘
        │ - Securely append to Cryptographic    │
        │   ledger chain block                  │
        │ - Decrement SOC Security Score        │
        │ - Increment Blocked Threat Telemetry  │
        └───────────────────────────────────────┘
```

Admins can click simulation triggers to verify RASP blocking:
*   **💉 SQL Injection:** Inject `' OR 1=1` into credential parameters.
*   **🖥️ Stored XSS:** Submits script blocks in form fields.
*   **🔄 CSRF tampering:** Submits state updates without valid tokens.
*   **🔑 JWT forgery:** Attempts to modify token signatures.
*   **🔓 Brute Force:** Simulates high-frequency login scripts.
*   **📤 DLP Leakage:** Attempts to download more than 5 script PDFs.

The WAF blocks the attack, triggers a warning toast, updates the Live Threat Level gauge, and appends a row to the **Real-Time Forensic Threat Log** containing the IP address and unique correlation ID.

---

## 🐛 Audited & Patched Vulnerabilities

EvalSync has been audited and secured against key vulnerability threats:
*   **CV-1 (Plaintext Credentials in JS):** Fixed. Removed demo credential arrays from client scripts; passwords are now securely evaluated on the server.
*   **CV-2 (Cred Leaks in .env):** Fixed. Commented credentials inside `.env` were removed and replaced with standard environment hashes.
*   **CV-3 (Unauthenticated Log Access):** Fixed. Added JWT/Session checks on `/api/audit/log` routes to prevent log tampering by anonymous users.
*   **HB-3 (Duplicate Auto-Scaler Worker IDs):** Fixed. Resolved worker array splicing duplication errors that crashed scaling run loops.
*   **HB-6 (Logout Session Clearing):** Fixed. Solved token persistence bugs that allowed back-button session hijacking after logging out.

---

## 🚀 Setup & Execution Guide

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
Open **`http://localhost:3000`** in your browser.

> [!NOTE]
> **Static Browser Fallback Mode:** EvalSync has a built-in fallback handler. If you open `index.html` directly from your hard drive (`file://` protocol), the client automatically bypasses backend server requirements and executes simulated authentication, keeping the UI fully interactive.

---

## 🐳 Container & Cluster Orchestration

### Docker Compose Stack
To run EvalSync integrated with a local Redis caching layer and RabbitMQ message broker:
```bash
docker compose up -d --build
```

### Kubernetes Production Manifest
Apply the cluster manifests located inside `k8s/deployment.yaml`:
```bash
kubectl apply -f k8s/deployment.yaml
```
The manifest configures:
- **Horizontal Pod Autoscaling (HPA):** Dynamically scales pods between 3 and 12 based on CPU load.
- **Ingress Controller:** Hardened routing endpoints.
- **Resource Constraints:** Sets explicit CPU and memory boundaries (Max: 512Mi, 500m) to stop denial-of-service node exhaustion.

---

## 🧪 Testing & Validation

Run the Jest integration suite to verify session management, rate limits, Helmet configurations, and WAF blocks:
```bash
# Run tests
npm test

# Run test coverage
npm run test:coverage
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
