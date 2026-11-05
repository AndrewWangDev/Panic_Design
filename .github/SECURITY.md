# Security Policy

## Supported Versions

We actively maintain and provide security updates for the current release stream of **panic.design**:

| Version | Supported          | Edge Compatibility Baseline |
| ------- | ------------------ | --------------------------- |
| 0.1.x   | :white_check_mark: | Cloudflare Workers 2026+    |
| < 0.1.0 | :x:                | Deprecated                  |

---

## Reporting a Vulnerability

We appreciate the efforts of security researchers and developers in making **panic.design** safer.

If you believe you have discovered a security vulnerability in the Control Plane (`panic_design`) or Data Plane (`Panic_Design_Gateway`), please **do not open a public issue or discuss it in public channels**.

### Preferred Reporting Method

1. **GitHub Private Vulnerability Reporting (PVR)**:
   Please submit an advisory privately through the **[GitHub Security Advisory](https://github.com/AndrewWangDev/panic_design/security/advisories/new)** dashboard. This allows for encrypted, secure collaboration between researchers and maintainers.

2. **Security Contact**:
   Alternatively, you can email our security team directly at:
   **`security@andrewwangdev.com`**

---

## Response & Triage SLA

We take every security concern seriously. When a report is received:

* **Initial Acknowledgment**: We will review and acknowledge your submission as soon as possible.
* **Triage & Investigation**: Our maintainers will validate the reproduction vector, verify impact on edge nodes or control plane services, and provide updates promptly.
* **Mitigation & Fix**: Validated vulnerabilities will be patched and deployed as quickly as feasible across both our edge runtime and control plane services.

---

## Coordinated Disclosure

We follow the principle of **Coordinated Vulnerability Disclosure (CVD)**:

1. Maintainers will work with the reporter to reproduce and verify the issue in a private environment.
2. A remediation patch will be developed, tested against our test suite, and deployed to production edge workers.
3. Once the mitigation is live and verified, a public security advisory with full credit to the researcher will be published.

---

## Scope & Critical Areas

Vulnerabilities of particular interest include:

* **Edge Isolation & Verification**: Fast-path cryptographic signature bypass (Web Crypto HS256), token forgery, or replay attacks.
* **Network & Ingress Security**: Server-Side Request Forgery (SSRF) bypasses against internal or loopback topologies.
* **Concurrency & Race Conditions**: Token quota exhaustion bypasses or Optimistic Concurrency Control (OCC) exploits.
* **State Synchronization**: Immediate revocation sync failures between Edge D1 and global proxy nodes.
