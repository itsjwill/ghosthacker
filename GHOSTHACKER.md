# 👻 Ghost Hacker

> **Adversarial AI Pentester** - Break your web app before anyone else does.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Based on Shannon](https://img.shields.io/badge/Based%20on-Shannon-purple)](https://github.com/KeygraphHQ/shannon)

Ghost Hacker is a fully autonomous AI pentester that delivers **actual exploits, not just alerts.** It hunts for attack vectors in your source code, then uses a real browser to execute live exploits — SQL injection, auth bypass, XSS, SSRF — proving the vulnerability is actually exploitable.

Built on [Shannon](https://github.com/KeygraphHQ/shannon) (96.15% success rate on XBOW Benchmark), Ghost Hacker adds **adversarial dual-agent exploitation** and **cross-scan collective memory** to push that even further.

> *Every Claude (coder) deserves their Ghost Hacker.*

---

## The Problem

Thanks to Claude Code, Cursor, and Copilot — your team ships code non-stop. But your penetration test? That happens **once a year.** For the other 364 days, you could be shipping vulnerabilities to production and not even know it.

Ghost Hacker closes that gap. Run it on every build. Get a pentester-grade report with working exploits in hours, not weeks.

---

## What Makes This Different

Most security tools give you a list of *potential* issues. Ghost Hacker **proves** they're exploitable:

| Tool | Approach | Output |
|------|----------|--------|
| **Burp Suite** | Manual + scanner | Alerts + suspected vulns |
| **OWASP ZAP** | Automated scanning | Vulnerability reports |
| **Snyk / Semgrep** | Static analysis | Code issues (no runtime proof) |
| **Ghost Hacker** | AI agents with source code + live browser | **Working exploits with copy-paste PoC** |

---

## Real Results

Ghost Hacker discovered **20+ critical vulnerabilities** in OWASP Juice Shop, including:

- **SQL Injection Auth Bypass** — Admin access with a single payload, no credentials needed
- **UNION Injection** — Full database dump: usernames, password hashes, roles
- **NoSQL Operator Injection** — Mass modified 28 records via `$ne` operator
- **XXE File Disclosure** — Read arbitrary files from the server filesystem
- **SSRF** — Internal service access, cloud metadata endpoint exposure

Every finding comes with **reproducible commands** — not theory, proof.

---

## Core Engine (from Shannon)

Ghost Hacker inherits Shannon's battle-tested pentesting pipeline:

### 13 AI Agents, 5 Phases

```
Phase 1: PRE-RECON ──→ nmap, subfinder, whatweb + source code analysis
Phase 2: RECON ──────→ Attack surface mapping, API inventory
Phase 3: VULN ───────→ 5 agents IN PARALLEL (injection, XSS, auth, authz, SSRF)
Phase 4: EXPLOIT ────→ 5 agents IN PARALLEL (prove each vuln is real)
Phase 5: REPORT ─────→ Executive-level security assessment
```

### Pipeline Parallelism (Not Barrier)

Each vuln→exploit pair runs independently. The XSS exploit can start while the injection vuln agent is still running. No "wait for all vuln agents to finish" bottleneck.

### Temporal Workflow Engine

- **Crash recovery** — Workflows resume automatically after worker restart
- **Smart retry** — 50 attempts with 5-30 minute backoff for billing/rate limits
- **Non-retryable errors** (auth, permissions) fail immediately, no wasted time
- **Queryable progress** — Real-time status via CLI or Temporal Web UI

### Claude Agent SDK — Full Autonomy

```typescript
{
  model: 'claude-sonnet-4-5',
  maxTurns: 10_000,           // Very long autonomous runs
  permissionMode: 'bypassPermissions',  // Full system access
  mcpServers: { playwright, helper }    // Real browser + tools
}
```

Each agent gets **up to 10,000 turns** of autonomous operation with full browser control via Playwright MCP. It can navigate your app, fill forms, handle 2FA/TOTP, and execute attacks — all without human intervention.

### Proof-Based Exploitation

Every claimed vulnerability must meet rigorous evidence levels:

| Level | Evidence Required | Classification |
|-------|-------------------|----------------|
| 1 | Error messages, timing differences | POTENTIAL (Low) |
| 2 | Boolean-blind working, UNION succeeds | POTENTIAL (Medium) |
| 3 | **Actual data extracted from database** | EXPLOITED |
| 4 | **Admin creds, PII, or RCE achieved** | EXPLOITED (CRITICAL) |

**Must reach Level 3+ with real data to mark as exploited.** Theory without proof = failure.

### Git Checkpoints

Before each agent runs, a git checkpoint is created. If the agent fails, the workspace rolls back. If it succeeds, the checkpoint is committed. Full audit trail of every action.

### OWASP Coverage

| Category | What It Finds |
|----------|--------------|
| **Injection** | SQL injection (UNION, blind, error-based), Command injection, NoSQL injection, XXE, YAML injection |
| **XSS** | Reflected, Stored, DOM-based, JSONP callback, Angular security bypass |
| **Auth** | Auth bypass, brute force, MD5 cracking, OAuth attacks, token replay |
| **AuthZ** | IDOR, role injection, horizontal privilege escalation, business logic bypass |
| **SSRF** | Internal service access, cloud metadata, HTTP method bypass |

### Security Tools Integration

| Tool | Purpose |
|------|---------|
| **nmap** | Network port scanning |
| **subfinder** | Subdomain discovery |
| **whatweb** | Web technology fingerprinting |
| **sqlmap** | SQL injection automation (escalation) |
| **Playwright** | Real browser for live exploit execution |

### Pentester-Grade Reports

The final report includes:
- Executive summary with business impact
- Every exploited vulnerability with severity rating
- **Copy-paste reproducible commands** for each exploit
- Full evidence chain: payload → response → extracted data
- Potential vulnerabilities blocked by external factors
- Difficulty analysis and routing decisions
- Adversarial battle results (Ghost Hacker enhancement)

---

## Ghost Hacker Enhancements

Everything above is inherited from Shannon. Here's what Ghost Hacker adds:

### 1. Difficulty Router

Shannon treats every vulnerability the same — 2-hour timeout, same approach. Ghost Hacker analyzes defenses **before** exploitation and routes intelligently:

| Signal | Difficulty Score |
|--------|-----------------|
| Prepared statements detected | +40 |
| WAF middleware present | +25 |
| Input validation | +20 |
| Output encoding | +15 |
| Framework protections | +10 each |
| Silent error handling | +15 |

**Routing decisions:**

| Score | Difficulty | Strategy | Timeout |
|-------|-----------|----------|---------|
| < 15 | Trivial | Quick confirm, 5 attempts | 30 min |
| 15-40 | Standard | Methodical OWASP workflow | 2 hours |
| 40-70 | Hardened | Bypass-heavy or adversarial | 2-4 hours |
| 70+ | Fortress | Adversarial dual-agent | 4 hours |

**Why this matters:** Don't waste 2 hours on a trivial reflected XSS. Don't give up after 15 attempts on a fortress-level blind SQLi behind a WAF.

### 2. Adversarial Dual-Agent Exploitation (CHAOS vs ORDER)

For hardened and fortress-level targets, Ghost Hacker deploys **two agents with opposing philosophies** that compete in parallel:

**🔴 CHAOS Agent**
```
"Start with the WEIRDEST payloads, not the obvious ones.
Combine techniques in unexpected ways.
Exploit parser differentials and edge cases.
If the obvious path is blocked, that's where you thrive."
```

**🔵 ORDER Agent**
```
"Follow proven patterns — highest success rate first.
OWASP methodology step by step.
Escalate systematically: manual → sqlmap → custom scripts.
The best exploit is one that works consistently."
```

**Why two agents?** The best pentesters aren't purely methodical OR purely creative — they switch between both. CHAOS finds bypasses ORDER would miss. ORDER provides reliability CHAOS lacks. Together they cover more attack surface than either alone.

**The JUDGE** evaluates both results on:
- Did they actually extract data?
- How many attempts did it take?
- Did they find a novel bypass?
- Is the PoC reproducible?

Winner's techniques get stored in collective memory.

### 3. Collective Memory (Cross-Scan Learning)

Shannon starts fresh every scan. Ghost Hacker **remembers.**

After each adversarial battle, winning techniques are stored with metadata:

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

**How memory helps:**
- Next scan against Django/Postgres? Start with time-based blind (82% success rate)
- Tried UNION injection 5 times against Express? Memory says it fails 90% of the time — skip it
- CHAOS discovered a unicode bypass? ORDER gets it in its recommended list next time

The more you scan, the smarter Ghost Hacker gets.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          GHOST HACKER PIPELINE                              │
└─────────────────────────────────────────────────────────────────────────────┘

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
  │                                   ├─→ 🔴 CHAOS Agent ──┐
  │                                   │                     ├──→ 🏛️ JUDGE
  │                                   └─→ 🔵 ORDER Agent ──┘       │
  │                                                                 ▼
  │                                                        COLLECTIVE MEMORY
  │                                                        (persists across scans)
  │
Phase 5: ENHANCED REPORT
  └→ Standard evidence + adversarial insights + difficulty analysis + memory stats
```

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

# Monitor
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

# Classic single-agent scan (faster, for CI/CD)
./ghosthacker start URL=https://app.example.com REPO=/path/to/code CLASSIC=true

# With custom config
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

## Sample Output

```
👻 GHOST HACKER - Adversarial AI Pentester

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
  ✅ INJ-001: EXPLOITED in 2 attempts (UNION injection, 12s)
  ✅ AUTH-001: EXPLOITED in 8 attempts (JWT confusion, 45s)

[ADVERSARIAL] ⚔️  CHAOS vs ORDER: INJ-003
  Difficulty: fortress
  Tech stack: django/postgres
  CHAOS will try: unicode_normalization, parser_differential, polyglot_payload...
  ORDER will try: time_based_blind, boolean_blind, error_based...

[JUDGE] 🏆 Winner: CHAOS
  Reasoning: CHAOS found bypass that ORDER missed using unicode_normalization
  Lessons learned:
    • Unconventional approach worked where methodical failed
    • unicode_normalization: 73% success rate against django (updated)

[ADVERSARIAL] ⚔️  CHAOS vs ORDER: XSS-001
  Difficulty: hardened

[JUDGE] 🏆 Winner: ORDER
  Reasoning: ORDER's methodical approach found mutation XSS in 12 attempts

[MEMORY] Saved 4 technique updates to collective memory

[REPORT] Generating enhanced security assessment...

════════════════════════════════════════
  SCAN COMPLETE
  Vulns found: 5 | Exploited: 4 | False positive: 1
  Adversarial battles: CHAOS 1 | ORDER 1
  Memory updates: 4 new techniques
  Duration: 47 minutes | Cost: $3.42
════════════════════════════════════════
```

---

## Configuration

### Environment Variables

```bash
ANTHROPIC_API_KEY=sk-ant-...          # Required
CLAUDE_CODE_MAX_OUTPUT_TOKENS=64000   # Recommended (prevents truncation)
```

### YAML Config (Optional)

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

Ghost Hacker supports complex auth flows including 2FA/TOTP, Google SSO, API keys, and basic auth — all configured via YAML with JSON Schema validation.

### Alternative Models (Experimental)

```bash
# OpenAI via router
OPENAI_API_KEY=sk-your-key
ROUTER_DEFAULT=openai,gpt-5.2

# Google Gemini via OpenRouter
OPENROUTER_API_KEY=sk-or-your-key
ROUTER_DEFAULT=openrouter,google/gemini-3-flash-preview
```

---

## When to Use What

| Situation | Mode | Why |
|-----------|------|-----|
| Quick security check | `CLASSIC=true` | Faster, single agent |
| Heavily defended app | Default (adversarial) | CHAOS finds what ORDER misses |
| CI/CD pipeline | `CLASSIC=true` | Predictable timing |
| Bug bounty hunting | Default + review memory | Memory learns from past scans |
| Same stack, repeat scans | Default | Memory knows what works |
| White-box audit | Default | Full source code analysis |

---

## Project Structure

```
ghosthacker/
├── ghosthacker                         # CLI entry point (ASCII banner + commands)
├── docker-compose.yml                  # Temporal + worker containers
├── configs/
│   ├── config-schema.json              # YAML config validation
│   ├── example-config.yaml             # Template config
│   └── router-config.json              # Multi-model routing
├── prompts/                            # AI prompt templates (444+ lines each)
│   ├── pre-recon-code.txt              # Source code analysis
│   ├── recon.txt                       # Attack surface mapping
│   ├── vuln-{injection,xss,auth,authz,ssrf}.txt
│   ├── exploit-{injection,xss,auth,authz,ssrf}.txt
│   ├── report-executive.txt            # Final report generation
│   └── shared/                         # Shared prompt partials
├── src/
│   ├── intelligence/                   # 👻 Ghost Hacker additions
│   │   ├── difficulty-router.ts        # Vulnerability difficulty analysis
│   │   └── adversarial-exploitation.ts # CHAOS vs ORDER + collective memory
│   ├── temporal/                       # Workflow orchestration
│   │   ├── workflows.ts               # Classic Shannon workflow
│   │   ├── enhanced-workflow.ts        # 👻 Adversarial workflow
│   │   ├── enhanced-activities.ts      # 👻 Routing + adversarial activities
│   │   ├── enhanced-worker.ts          # 👻 Worker with all activities
│   │   ├── activities.ts              # Core agent activities
│   │   └── shared.ts                   # Types + query handlers
│   ├── ai/
│   │   ├── claude-executor.ts          # Claude Agent SDK integration
│   │   ├── message-handlers.ts         # Stream message processing
│   │   └── router-utils.ts            # Multi-model routing
│   ├── audit/                          # Crash-safe logging system
│   └── prompts/
│       └── prompt-manager.ts           # Template variable injection
├── mcp-server/                         # Custom MCP tools
│   └── src/tools/
│       ├── save-deliverable.ts         # Evidence file saving
│       └── generate-totp.ts            # 2FA token generation
├── sample-reports/                     # Real scan outputs
│   ├── shannon-report-juice-shop.md    # 20+ vulns found
│   ├── shannon-report-crapi.md
│   └── shannon-report-capital-api.md
└── collective-memory.json              # 👻 Cross-scan learning (generated)
```

---

## Benchmark

Shannon Lite (Ghost Hacker's base) achieves a **96.15% success rate** on the hint-free, source-aware XBOW Benchmark.

Ghost Hacker's adversarial mode is designed to push that number higher on hardened targets where a single agent's approach isn't enough.

---

## Cost

Ghost Hacker uses Claude Sonnet 4.5 by default:
- **Typical scan:** $2-5 (simple app, classic mode)
- **Complex scan:** $5-15 (large app, adversarial mode)
- **Adversarial battles:** ~2x cost per hardened vuln (two agents running)
- Built-in **spending cap detection** — won't silently burn through your budget

Use `CLASSIC=true` for CI/CD to keep costs predictable. Use adversarial mode for thorough audits where finding that one extra bypass justifies the cost.

---

## Credits

Ghost Hacker is built on [Shannon](https://github.com/KeygraphHQ/shannon) by [Keygraph](https://keygraph.io). Shannon provides the core pentesting pipeline, Claude Agent SDK integration, Temporal workflow infrastructure, prompt engineering, audit system, and MCP tooling.

**Ghost Hacker adds:**
- Difficulty-based vulnerability routing
- Adversarial dual-agent exploitation (CHAOS vs ORDER)
- Cross-scan collective memory system
- Enhanced CLI with `./ghosthacker` commands

---

## License

AGPL-3.0 (same as Shannon)

---

## Disclaimer

Ghost Hacker is for **authorized security testing only.** White-box only — requires access to application source code. Only test systems you own or have explicit written permission to test. The authors are not responsible for misuse.

---

<p align="center">
  <b>👻 Happy Hacking</b>
</p>
