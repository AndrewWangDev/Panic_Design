# Contributing to panic.design

Thank you for your interest in contributing to **panic.design**! 

panic.design is an open-source, zero-intrusion, AI-driven edge chaos engineering gateway built on Cloudflare Workers, Next.js 16, OpenNext, and Hono. We welcome contributions ranging from bug fixes and algorithm optimizations to new fault injection patterns and documentation enhancements.

---

## Architecture Overview

Before making changes, it is helpful to understand our dual-plane decoupled architecture:

```text
[ Client ] ──► [ panic.design Data Plane (Hono) ] ──► [ Target Upstream Host ]
                      ▲ (Edge D1 / Auth Secret)
                      │
           [ panic.design Control Plane (Next.js) ]
           - AIOps Copilot (Workers AI: Llama 4 Scout 17B)
           - Quota & Token Management (Prisma D1 + OCC)
           - LGPA Spatial Sandbox & Interactive Console
```

* **Control Plane (`panic_design`)**: Next.js App Router running on Cloudflare Workers via OpenNext. Handles developer authentication (NextAuth v5), token minting, quota rate limits, and Workers AI prompt deduction.
* **Data Plane (`Panic_Design_Gateway`)**: High-performance Hono proxy deployed across 300+ global edge locations. Implements sub-millisecond in-memory JWT cryptographic validation and zero-overhead fault injection.

---

## Local Development Setup

### Prerequisites

* **Node.js**: `v20.x` or later (LTS recommended)
* **npm**: `v10.x` or later
* **Cloudflare Wrangler CLI**: `v4.95+` (`npm install -g wrangler`)
* **Git**: Installed and configured

### 1. Clone & Install

```bash
git clone https://github.com/AndrewWangDev/panic_design.git
cd panic_design
npm install
```

### 2. Configure Environment

Create a `.dev.vars` or `.env.local` file in the root directory:

```env
AUTH_SECRET="your-32-byte-hex-random-secret"
AUTH_CLIENT_ID="your-github-oauth-client-id"
AUTH_CLIENT_SECRET="your-github-oauth-client-secret"
TURNSTILE_SECRET_KEY="1x0000000000000000000000000000000AA"
```

> **Note**: Never commit `.dev.vars` or secrets to git. The repository `.gitignore` is configured to prevent accidental leakage.

### 3. Initialize Local D1 Database

```bash
npx prisma generate
npx wrangler d1 execute DB --local --file=./prisma/schema.sql
```

### 4. Run Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to access the local console.

---

## Code Quality & Verification Gates

Before submitting any code, please ensure all quality checks pass locally:

### 1. Unit & Concurrency Tests

```bash
npm test
```
We use **Vitest** for testing algorithm mathematics (LGPA great-circle calculations), SSRF / Hostname parsers, and Prisma Optimistic Concurrency Control (OCC) logic. All tests must pass.

### 2. Code Linting

```bash
npm run lint
```
Our ESLint configuration enforces standard Next.js and TypeScript conventions. Ensure zero lint errors.

### 3. Production Build Validation

```bash
npm run build
```
Validates TypeScript typings, Prisma client generation, and Next.js Turbopack compilation.

---

## Commit Guidelines

We adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:

* `feat:` A new feature or algorithm enhancement
* `fix:` A bug fix or boundary protection
* `docs:` Documentation changes
* `test:` Adding or refactoring test cases
* `refactor:` Code restructuring without changing behavior
* `perf:` Performance optimizations
* `chore:` Build process or auxiliary tool updates

Example:
```text
feat(lgpa): introduce geodesic distance interpolation for edge drift
fix(security): sanitize bracketed ipv6 host formats and port ranges
```

---

## Submitting a Pull Request

1. **Fork the Repository**: Create your branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. **Make Changes**: Write clean, self-documenting code. Add unit tests in `tests/` for new features or bug fixes.
3. **Verify Locally**: Run `npm test`, `npm run lint`, and `npm run build`.
4. **Push & Create PR**: Push your branch to GitHub and open a Pull Request using our [PR Template](.github/PULL_REQUEST_TEMPLATE.md).
5. **Review Process**: Maintainers will review your PR and provide constructive feedback. Once approved, commits will be squashed and merged into `main`.

---

## Community & Conduct

All contributors are expected to uphold our [Code of Conduct](.github/CODE_OF_CONDUCT.md). Please report any unacceptable behavior to `me@andrewwangdev.com`.
