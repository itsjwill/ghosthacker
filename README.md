# Ghost Hacker — Autonomous AI Pentester That Delivers Working Exploits, Not Alerts

### The open-source alternative to Burp Suite, Snyk, Qualys, and manual pentests

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/itsjwill/ghosthacker?style=social)](https://github.com/itsjwill/ghosthacker)
[![Updated 2026](https://img.shields.io/badge/Updated-2026-brightgreen)](https://github.com/itsjwill/ghosthacker)
[![Claude Agent SDK](https://img.shields.io/badge/Powered%20by-Claude%20Agent%20SDK-purple)](https://docs.anthropic.com/en/docs/agents-and-tools/claude-agent-sdk)
[![96.15% XBOW](https://img.shields.io/badge/XBOW%20Benchmark-96.15%25-gold)](https://xbow.com)

Ghost Hacker is a fully autonomous AI pentester that **finds real vulnerabilities and proves they're exploitable** — SQL injection, auth bypass, XSS, SSRF — using 13 AI agents with a real browser. No false positives. No theory. Just working exploits with copy-paste proof-of-concept commands.

Built on [Shannon](https://github.com/KeygraphHQ/shannon) (96.15% XBOW Benchmark success rate), enhanced with **adversarial dual-agent exploitation (CHAOS vs ORDER)** and **cross-scan collective memory** that gets smarter with every scan.

> *Your team ships code every day. Your pentest happens once a year. Ghost Hacker closes that gap.*

---

## Why Ghost Hacker?

Most security tools give you a list of *possible* issues. Ghost Hacker **proves** they're exploitable by executing live attacks and extracting real data.

### Cost Comparison: Ghost Hacker vs. Paid Alternatives

| Tool | Type | Price | Output | False Positives |
|------|------|-------|--------|-----------------|
| **Ghost Hacker** | **AI Pentester** | **Free + ~$3-15 API cost/scan** | **Working exploits with PoC** | **Near zero** |
| Burp Suite Pro | Scanner + Manual | $449/yr | Alerts + suspected vulns | Medium |
| Snyk | SAST/SCA | $25-98/dev/mo | Code issues (no runtime proof) | High |
| Qualys WAS | Cloud Scanner | ~$2,000+/yr | Vulnerability reports | Medium |
| HackerOne Pentest | Human Pentesters | $10,000-50,000/engagement | Expert findings | Low |
| Acunetix | DAST Scanner | $4,500+/yr | Scan reports | Medium-High |

**Bottom line:** Ghost Hacker gives you pentest-grade results for the cost of a few API calls.

---

## Real Results — 20+ Critical Vulns in OWASP Juice Shop

Ghost Hacker discovered and **proved** 20+ critical vulnerabilities, including:

- **SQL Injection Auth Bypass** — Admin access with a single payload, zero credentials needed
- **UNION Injection** — Full database dump: usernames, password hashes, roles, emails
- **NoSQL Operator Injection** — Mass modified 28 records via `$ne` operator
- **XXE File Disclosure** — Read arbitrary server files through XML entity injection
- **SSRF** — Internal service access + cloud metadata endpoint exposure (AWS keys, tokens)

Every finding includes **reproducible commands** — not theory, proof. [See full sample report](sample-reports/)

---

## How It Works — 13 AI Agents, 5 Phases

```
Phase 1: PRE-RECON ────→ nmap + subfinder + whatweb + source code analysis
Phase 2: RECON ─────────→ Attack surface mapping, API inventory, input vectors
Phase 3: VULN ──────────→ 5 agents IN PARALLEL (injection, XSS, auth, authz, SSRF)
Phase 4: EXPLOIT ───────→ 5 agents IN PARALLEL (prove each vuln is exploitable)
Phase 5: REPORT ────────→ Executive-level security assessment with evidence
```

Each vuln→exploit pair runs independently. The XSS exploit starts while the injection agent is still running. No "wait for all" bottleneck.

---

## What Makes Ghost Hacker Different

### 1. Difficulty Router — Smart Resource Allocation

Ghost Hacker analyzes defenses **before** exploitation and routes intelligently:

| Defense Signal | Score | Detection |
|---------------|-------|-----------|
| Prepared statements | +40 | Source code analysis |
| WAF middleware | +25 | Response pattern matching |
| Input validation | +20 | Code path tracing |
| Output encoding | +15 | Template analysis |
| Silent error handling | +15 | Error response fingerprinting |

**Routing decisions:**

| Score | Difficulty | Strategy | Timeout |
|-------|-----------|----------|---------|
| < 15 | Trivial | Quick confirm, 5 attempts | 30 min |
| 15-40 | Standard | Methodical OWASP workflow | 2 hours |
| 40-70 | Hardened | Bypass-heavy or adversarial | 2-4 hours |
| 70+ | Fortress | Adversarial dual-agent (CHAOS vs ORDER) | 4 hours |

Don't waste 2 hours on a trivial reflected XSS. Don't give up after 15 attempts on a fortress-level blind SQLi behind a WAF.

### 2. Adversarial Dual-Agent Exploitation (CHAOS vs ORDER)

For hardened targets, Ghost Hacker deploys **two competing agents** in parallel:

**CHAOS Agent** — The creative rule-breaker
```
Start with the WEIRDEST payloads, not the obvious ones.
Combine techniques in unexpected ways.
Exploit parser differentials and edge cases.
If the obvious path is blocked, that's where you thrive.
```

**ORDER Agent** — The methodical professional
```
Follow proven patterns — highest success rate first.
OWASP methodology step by step.
Escalate systematically: manual → sqlmap → custom scripts.
The best exploit is one that works consistently.
```

A **JUDGE** evaluates both results: Did they extract real data? How many attempts? Novel bypass? Reproducible PoC? Winner's techniques get stored in collective memory.

### 3. Collective Memory — Gets Smarter Every Scan

Ghost Hacker **remembers** what works. After each adversarial battle, winning techniques are stored:

```json
{
  "time_based_blind": {
    "successRate": 0.82,
    "avgTimeMs": 45000,
    "sampleSize": 47,
    "bestAgainstStack": ["django", "postgres"]
  },
  "unicode_normalization": {
    "successRate": 0.73,
    "avgTimeMs": 8000,
    "sampleSize": 12,
    "bestAgainstStack": ["express", "mongodb"]
  }
}
```

Next scan against Django/Postgres? Start with time-based blind (82% success rate). Tried UNION injection 5 times against Express? Memory says it fails 90% — skip it. The more you scan, the smarter Ghost Hacker gets.

---

## Quick Start

```bash
# Clone
git clone https://github.com/itsjwill/ghosthacker.git
cd ghosthacker

# Configure
cp .env.example .env
# Edit .env: ANTHROPIC_API_KEY=your-key

# Run (adversarial mode is default)
./ghosthacker start URL=https://your-app.com REPO=/path/to/source

# Monitor progress
./ghosthacker logs
./ghosthacker query ID=ghosthacker-1234567890
open http://localhost:8233  # Temporal UI
```

### Prerequisites

- **Docker** — [Install Docker](https://docs.docker.com/get-docker/)
- **Anthropic API key** — [Get one here](https://console.anthropic.com)

---

## Commands

```bash
# Adversarial scan (default — CHAOS vs ORDER on hard targets)
./ghosthacker start URL=https://app.example.com REPO=/path/to/code

# Classic single-agent scan (faster, cheaper, good for CI/CD)
./ghosthacker start URL=https://app.example.com REPO=/path/to/code CLASSIC=true

# With custom auth config (2FA, SSO, form login)
./ghosthacker start URL=https://app.example.com REPO=/path/to/code CONFIG=./configs/my-config.yaml

# View real-time logs
./ghosthacker logs

# Query workflow progress
./ghosthacker query ID=ghosthacker-1234567890

# View collective memory stats
./ghosthacker memory

# Stop (preserves data)
./ghosthacker stop

# Stop and clean everything
./ghosthacker stop CLEAN=true
```

---

## When to Use What

| Situation | Mode | Why |
|-----------|------|-----|
| Quick security check | `CLASSIC=true` | Faster, single agent, $2-5 |
| Heavily defended app | Default (adversarial) | CHAOS finds what ORDER misses |
| CI/CD pipeline | `CLASSIC=true` | Predictable timing and cost |
| Bug bounty hunting | Default + review memory | Memory learns from past scans |
| Same stack, repeat scans | Default | Memory knows what works |
| Pre-production audit | Default | Full source code + live browser analysis |

---

## Sample Output

```
GHOST HACKER - Adversarial AI Pentester

[PRE-RECON] Scanning target with nmap, subfinder, whatweb...
[PRE-RECON] Analyzing source code for vulnerability patterns...
[RECON] Mapping attack surface: 47 endpoints, 23 input vectors...

[ROUTER] Analyzing vulnerability difficulty...
  INJ-001: trivial   → quick_confirm  (5 attempts, 30min)
  INJ-002: standard  → methodical     (15 attempts, 2hr)
  INJ-003: fortress  → adversarial    (50 attempts, 4hr)
  XSS-001: hardened  → bypass_heavy   (30 attempts, 4hr)
  AUTH-001: standard → methodical     (15 attempts, 2hr)

[EXPLOIT] Running single-agent on 2 trivial/standard vulns...
  INJ-001: EXPLOITED in 2 attempts (UNION injection, 12s)
  AUTH-001: EXPLOITED in 8 attempts (JWT confusion, 45s)

[ADVERSARIAL] CHAOS vs ORDER: INJ-003
  Difficulty: fortress | Tech stack: django/postgres
  CHAOS: unicode_normalization, parser_differential, polyglot_payload...
  ORDER: time_based_blind, boolean_blind, error_based...

[JUDGE] Winner: CHAOS
  unicode_normalization bypass succeeded where methodical approach failed

[MEMORY] Saved 4 technique updates to collective memory

[REPORT] Generating enhanced security assessment...

  SCAN COMPLETE
  Vulns found: 5 | Exploited: 4 | False positive: 1
  Adversarial battles: CHAOS 1 | ORDER 1
  Memory updates: 4 new techniques
  Duration: 47 minutes | Cost: $3.42
```

---

## OWASP Coverage

| Category | What Ghost Hacker Finds & Exploits |
|----------|-----------------------------------|
| **Injection** | SQL injection (UNION, blind, error-based, time-based), Command injection, NoSQL injection, XXE, YAML injection, SSTI |
| **XSS** | Reflected, Stored, DOM-based, JSONP callback injection, Angular security bypass, HTML injection |
| **Auth** | Auth bypass, brute force, MD5 cracking, OAuth attacks, token replay, JWT confusion, weak credentials |
| **AuthZ** | IDOR, role injection, horizontal/vertical privilege escalation, business logic bypass |
| **SSRF** | Internal service access, cloud metadata (AWS/GCP/Azure), HTTP method bypass |

### Proof-Based Evidence Levels

| Level | Evidence Required | Classification |
|-------|-------------------|----------------|
| 1 | Error messages, timing differences | POTENTIAL (Low) |
| 2 | Boolean-blind working, UNION succeeds | POTENTIAL (Medium) |
| 3 | **Actual data extracted from database** | EXPLOITED |
| 4 | **Admin creds, PII, or RCE achieved** | EXPLOITED (CRITICAL) |

**Must reach Level 3+ with real data to mark as exploited.** Theory without proof = failure.

---

## Architecture

```
                        GHOST HACKER PIPELINE

Phase 1: PRE-RECON (sequential)
  └→ nmap + subfinder + whatweb + source code analysis

Phase 2: RECON (sequential)
  └→ Attack surface mapping, API inventory, input vector identification

Phase 3-4: ADAPTIVE EXPLOITATION
  │
  ├─→ DIFFICULTY ROUTER analyzes each vuln from Phase 3
  │     │
  │     ├─→ TRIVIAL + STANDARD ──→ Single agent (parallel, fast)
  │     │
  │     └─→ HARDENED + FORTRESS ──→ ADVERSARIAL MODE
  │                                   │
  │                                   ├─→ CHAOS Agent ──┐
  │                                   │                  ├──→ JUDGE
  │                                   └─→ ORDER Agent ──┘      │
  │                                                            ▼
  │                                                   COLLECTIVE MEMORY
  │                                                   (persists across scans)
  │
Phase 5: ENHANCED REPORT
  └→ Evidence chain + adversarial insights + difficulty analysis + memory stats
```

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| **AI Engine** | Claude Sonnet 4.5 via [Claude Agent SDK](https://docs.anthropic.com/en/docs/agents-and-tools/claude-agent-sdk) (10,000 max turns) |
| **Browser Automation** | Playwright MCP (real Chrome, headless) |
| **Workflow Orchestration** | Temporal (crash recovery, smart retry, queryable progress) |
| **Security Tools** | nmap, subfinder, whatweb, sqlmap, schemathesis |
| **Container** | Docker + Chainguard Wolfi (minimal attack surface) |
| **Language** | TypeScript |
| **MCP Tools** | save_deliverable, generate_totp (2FA support) |

### Key Capabilities

- **Crash Recovery** — Temporal workflows resume automatically after restart
- **Smart Retry** — 50 attempts with 5-30 min backoff for billing/rate limits
- **Git Checkpoints** — Every agent creates a rollback point before running
- **Parallel Execution** — 5 concurrent agents in vuln/exploit phases
- **10,000 Autonomous Turns** — Each agent gets extensive operation time
- **Full Browser Control** — Navigate, fill forms, handle 2FA/TOTP, execute attacks
- **Queryable Progress** — Real-time status via CLI or Temporal Web UI

---

## Configuration

### Environment Variables

```bash
ANTHROPIC_API_KEY=sk-ant-...          # Required
CLAUDE_CODE_MAX_OUTPUT_TOKENS=64000   # Recommended (prevents truncation)
```

### YAML Config (Optional — Auth, 2FA, Custom Flows)

```yaml
authentication:
  type: form
  loginUrl: https://app.example.com/login
  credentials:
    username: test@example.com
    password: testpass123
  mfa:
    type: totp
    secret: JBSWY3DPEHPK3PXP

adversarial:
  enabled: true
  minDifficultyForAdversarial: hardened
  memoryPath: ./collective-memory.json
```

Supports form login, Google SSO, API keys, basic auth, and 2FA/TOTP — all with JSON Schema validation.

### Alternative Models (Experimental)

```bash
# OpenAI
OPENAI_API_KEY=sk-your-key
ROUTER_DEFAULT=openai,gpt-5.2

# Google Gemini via OpenRouter
OPENROUTER_API_KEY=sk-or-your-key
ROUTER_DEFAULT=openrouter,google/gemini-3-flash-preview
```

---

## Project Structure

```
ghosthacker/
├── ghosthacker                        # CLI entry point (ASCII banner + commands)
├── docker-compose.yml                 # Temporal + worker containers
├── Dockerfile                         # Chainguard Wolfi (minimal attack surface)
├── configs/
│   ├── config-schema.json             # YAML config validation
│   ├── example-config.yaml            # Template config
│   └── router-config.json             # Multi-model routing
├── prompts/                           # AI prompt templates (444+ lines each)
│   ├── pre-recon-code.txt             # Source code analysis
│   ├── recon.txt                      # Attack surface mapping
│   ├── vuln-{injection,xss,auth,authz,ssrf}.txt
│   ├── exploit-{injection,xss,auth,authz,ssrf}.txt
│   ├── report-executive.txt           # Final report generation
│   └── shared/                        # Shared prompt partials
├── src/
│   ├── intelligence/                  # Ghost Hacker additions
│   │   ├── difficulty-router.ts       # Vulnerability difficulty analysis
│   │   └── adversarial-exploitation.ts # CHAOS vs ORDER + collective memory
│   ├── temporal/                      # Workflow orchestration
│   │   ├── workflows.ts              # Classic pipeline workflow
│   │   ├── enhanced-workflow.ts       # Adversarial workflow
│   │   ├── enhanced-activities.ts     # Routing + adversarial activities
│   │   ├── enhanced-worker.ts         # Worker with all activities
│   │   ├── activities.ts             # Core agent activities
│   │   └── shared.ts                  # Types + query handlers
│   ├── ai/
│   │   ├── claude-executor.ts         # Claude Agent SDK integration
│   │   ├── message-handlers.ts        # Stream message processing
│   │   └── router-utils.ts           # Multi-model routing
│   ├── audit/                         # Crash-safe logging system
│   └── prompts/
│       └── prompt-manager.ts          # Template variable injection
├── mcp-server/                        # Custom MCP tools
│   └── src/tools/
│       ├── save-deliverable.ts        # Evidence file saving
│       └── generate-totp.ts           # 2FA token generation
├── sample-reports/                    # Real scan outputs (20+ vulns found)
└── collective-memory.json             # Cross-scan learning (generated after scans)
```

---

## Benchmark

Ghost Hacker's base engine achieves a **96.15% success rate** on the hint-free, source-aware [XBOW Benchmark](https://xbow.com) — the industry standard for measuring AI pentesting capability.

The adversarial mode (CHAOS vs ORDER) pushes this higher on hardened targets where a single agent's methodology isn't enough.

---

## Cost

| Mode | Typical Cost | Best For |
|------|-------------|----------|
| Classic (`CLASSIC=true`) | $2-5 per scan | CI/CD, quick checks |
| Adversarial (default) | $5-15 per scan | Thorough audits, hardened targets |
| Adversarial + Memory | Decreasing over time | Repeat scans on same stack |

Built-in **spending cap detection** — won't silently burn through your API budget.

---

## Security & Ethics

Ghost Hacker is for **authorized security testing only.** This is a white-box tool — it requires access to application source code.

**Only test systems you own or have explicit written permission to test.**

The tool is designed for:
- Vulnerability assessment and security audits
- Pre-production security verification
- Bug bounty research (with authorization)
- Security report generation
- Developer self-testing ("hack yourself before someone else does")

---

## Credits

Ghost Hacker is built on [Shannon](https://github.com/KeygraphHQ/shannon) by [Keygraph](https://keygraph.io), which provides the core pentesting pipeline, Claude Agent SDK integration, Temporal workflow infrastructure, and audit system.

**Ghost Hacker adds:**
- Difficulty-based vulnerability routing (smart resource allocation)
- Adversarial dual-agent exploitation (CHAOS vs ORDER competing agents)
- Cross-scan collective memory (gets smarter every scan)
- Enhanced CLI with `./ghosthacker` commands

---

## Contributing

Ghost Hacker is open source under AGPL-3.0. Contributions welcome:

1. Fork the repo
2. Create a feature branch
3. Submit a PR with tests

---

## License

AGPL-3.0 — Free to use, modify, and distribute. Derivative works must also be open source.

---

<p align="center">
  <b>Ghost Hacker — Hack yourself before someone else does.</b>
  <br><br>
  <a href="https://www.skool.com/ai-elite-9507/about?ref=67521860944147018da6145e3db6e51c">
    <img src="https://img.shields.io/badge/Join%20The%20Agentic%20Advantage-Learn%20AI%20Security-blueviolet?style=for-the-badge" alt="Join The Agentic Advantage">
  </a>
</p>