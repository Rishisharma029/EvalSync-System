# Security Policy — EvalSync Enterprise 6.0

## Supported Versions

Security updates and active patches are backported only for the current major release branch (6.x). Legacy versions are not supported.

| Version | Supported          | Security Assessment |
| ------- | ------------------ | ------------------- |
| 6.x     | :white_check_mark: | Active Patching     |
| 4.x     | :x:                | Legacy              |
| < 4.0   | :x:                | Unsupported         |

---

## Zero-Trust Security Standard

EvalSync Enterprise 6.0 aligns with **OWASP ASVS (Application Security Verification Standard) Level 3** design patterns, incorporating:
1.  **WAF & RASP Filtering:** Gateway-level inspection blocking SQL Injection (SQLi), Cross-Site Scripting (XSS), XML Entities (XXE), and Path Traversal payloads before route processing.
2.  **Adaptive Authentication:** Computes risk profiles using impossible travel velocity, device fingerprinting, and progressive brute-force lockout delays.
3.  **HSM Cryptographic Verification:** Simulated Hardware Security Module (FIPS 140-2 envelope signing) verifies answer script file uploads.
4.  **Immutable Block Ledger Chain:** Cryptographically chains all changes using SHA-256 blocks, making files tamper-evident.
5.  **DLP Limits:** Restricts evaluators to a maximum of 5 script downloads per session window.

---

## Reporting a Vulnerability

If you discover a security vulnerability or exploit in the system architecture, **do not open a public issue.** Public disclosures bypass security protocols.

Instead, report it privately to our cybersecurity maintainer at:
📧 **i.rishisharma2007@gmail.com**

Please include the following details in your report:
*   A summary description of the vulnerability.
*   Step-by-step reproduction instructions or a Proof of Concept (PoC) script.
*   The potential impact on data integrity or service availability.

### Security Response SLA
*   **Initial Response:** Within 48 hours of submission.
*   **Vulnerability Triage:** Within 5 business days.
*   **Patch Release Timeline:** Security fixes are released as micro-patches directly to the `master` branch.
