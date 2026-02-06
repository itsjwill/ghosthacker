# 👻 Ghost Hacker

> **Adversarial AI Pentester** - CHAOS vs ORDER dual-agent exploitation with collective memory

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)

Ghost Hacker is an enhanced fork of [Shannon](https://github.com/KeygraphHQ/shannon) that introduces **adversarial multi-agent exploitation** and **cross-scan learning**.

Instead of a single AI agent methodically testing vulnerabilities, Ghost Hacker deploys two agents with opposing philosophies to compete on hardened targets:

- **🔴 CHAOS** - Creative, unconventional, edge cases first
- **🔵 ORDER** - Methodical, by-the-book, follows OWASP religiously

A **JUDGE** evaluates both results, picks the winner, and stores winning techniques in **collective memory** for future scans.

---

## 🎯 What's Different from Shannon?

| Feature | Shannon | Ghost Hacker |
|---------|---------|--------------|
| **Agent Strategy** | Single agent, one approach | Dual adversarial agents |
| **Difficulty Awareness** | Treats all vulns the same | Routes by difficulty level |
| **Learning** | None - fresh each scan | Collective memory across scans |
| **Hard Targets** | Same timeout/approach | Extended time + adversarial mode |
| **False Positives** | Agent decides | Research mode for fortress-level |

---

## 🏗️ Architecture

```
                         ┌─────────────────────────────────────┐
                         │         DIFFICULTY ROUTER           │
                         │  Analyzes defenses, routes strategy │
                         └──────────────────┬──────────────────┘
                                            │
               ┌────────────────────────────┼────────────────────────────┐
               │                            │                            │
               ▼                            ▼                            ▼
    ┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
    │     TRIVIAL      │         │    STANDARD      │         │ HARDENED/FORTRESS│
    │   Quick Confirm  │         │    Methodical    │         │   ADVERSARIAL    │
    │   5 attempts     │         │   15 attempts    │         │                  │
    │   30min timeout  │         │   2hr timeout    │         │  ┌─────┐ ┌─────┐ │
    └──────────────────┘         └──────────────────┘         │  │CHAOS│ │ORDER│ │
                                                              │  └──┬──┘ └──┬──┘ │
                                                              │     │       │    │
                                                              │     └───┬───┘    │
                                                              │         ▼        │
                                                              │    ┌────────┐    │
                                                              │    │ JUDGE  │    │
                                                              │    └────────┘    │
                                                              └──────────────────┘
                                                                        │
                                                                        ▼
                                                              ┌──────────────────┐
                                                              │ COLLECTIVE MEMORY │
                                                              │  Learns winning   │
                                                              │  techniques for   │
                                                              │  future scans     │
                                                              └──────────────────┘
```

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/ghosthacker.git
cd ghosthacker

# Configure
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env

# Run
./ghosthacker start URL=https://your-app.com REPO=/path/to/source
```

---

## 🎮 Commands

```bash
# Start a scan with adversarial mode (default)
./ghosthacker start URL=https://app.example.com REPO=/path/to/code

# Start in classic single-agent mode
./ghosthacker start URL=https://app.example.com REPO=/path/to/code CLASSIC=true

# View logs
./ghosthacker logs

# Query workflow progress
./ghosthacker query ID=ghosthacker-1234567890

# View collective memory stats
./ghosthacker memory

# Stop everything
./ghosthacker stop

# Stop and clean all data
./ghosthacker stop CLEAN=true
```

---

## 🧠 How Adversarial Mode Works

### 1. Difficulty Routing

Before exploitation, Ghost Hacker analyzes each vulnerability:

| Signal | Score |
|--------|-------|
| Prepared statements detected | +40 |
| WAF middleware present | +25 |
| Input validation | +20 |
| Output encoding | +15 |
| Framework protections | +10 each |

**Routing:**
- **< 15** → Trivial (quick confirm)
- **15-40** → Standard (methodical)
- **40-70** → Hardened (bypass heavy or adversarial)
- **> 70** → Fortress (adversarial with extended timeout)

### 2. CHAOS vs ORDER

For hardened targets, two agents compete:

**🔴 CHAOS Agent:**
```
"Start with the WEIRDEST payloads, not the obvious ones.
Combine techniques in unexpected ways.
If the obvious path is blocked, that's where you thrive."
```

**🔵 ORDER Agent:**
```
"Follow proven patterns - highest success rate first.
OWASP methodology step by step.
The best exploit is one that works consistently."
```

### 3. Judgement

The JUDGE evaluates:
- Did they actually extract data?
- How many attempts did it take?
- Did they find a novel bypass?
- Is the PoC reproducible?

**Winner's techniques get stored in collective memory.**

### 4. Collective Memory

Over time, Ghost Hacker learns:

```json
{
  "techniques": {
    "time_based_blind": {
      "successRate": 0.82,
      "avgTimeMs": 45000,
      "sampleSize": 47,
      "bestAgainstStack": ["django", "postgres"]
    },
    "union_injection": {
      "successRate": 0.65,
      "avgTimeMs": 12000,
      "sampleSize": 89
    }
  }
}
```

Next scan against Django/Postgres? Start with time-based blind.

---

## 📊 Sample Output

```
[ROUTER] Analyzing vulnerability difficulty...
  INJ-001: trivial → quick_confirm (5 attempts)
  INJ-002: standard → methodical (15 attempts)
  INJ-003: fortress → research_mode (50 attempts)
  XSS-001: hardened → bypass_heavy (30 attempts)

[ENHANCED] Running single-agent exploitation on 2 vulns
[ENHANCED] Running ADVERSARIAL exploitation on 2 vulns

[ADVERSARIAL] ⚔️  CHAOS vs ORDER: INJ-003
  Difficulty: fortress
  Tech stack: django/postgres
  CHAOS will try: unicode_normalization, parser_differential, polyglot_payload...
  ORDER will try: time_based_blind, boolean_blind, error_based...

[JUDGE] 🏆 Winner: CHAOS
  Reasoning: CHAOS found bypass that ORDER missed using techniques: unicode_normalization
  Lessons learned:
    • Unconventional approach worked where methodical failed
    • Techniques to remember: unicode_normalization, parser_differential

[MEMORY] Saved collective memory (2 new techniques recorded)
```

---

## 🔧 Configuration

### Environment Variables

```bash
ANTHROPIC_API_KEY=sk-ant-...      # Required
CLAUDE_CODE_MAX_OUTPUT_TOKENS=64000  # Recommended
```

### YAML Config (Optional)

```yaml
authentication:
  type: form
  loginUrl: https://app.example.com/login
  credentials:
    username: test@example.com
    password: testpass123

adversarial:
  enabled: true
  minDifficultyForAdversarial: hardened  # or fortress
  memoryPath: ./collective-memory.json
```

---

## 📁 Project Structure

```
ghosthacker/
├── ghosthacker                    # CLI entry point
├── src/
│   ├── intelligence/
│   │   ├── difficulty-router.ts   # Vulnerability difficulty analysis
│   │   └── adversarial-exploitation.ts  # CHAOS vs ORDER system
│   ├── temporal/
│   │   ├── enhanced-workflow.ts   # Adversarial Temporal workflow
│   │   ├── enhanced-activities.ts # Routing + adversarial activities
│   │   └── enhanced-worker.ts     # Worker with enhanced activities
│   └── ...                        # Original Shannon code
├── prompts/                       # AI prompts
├── configs/                       # Example configs
└── collective-memory.json         # Cross-scan learning (generated)
```

---

## 🆚 When to Use What

| Situation | Recommendation |
|-----------|----------------|
| Quick security check | `CLASSIC=true` |
| Heavily defended app | Default (adversarial) |
| CI/CD pipeline | `CLASSIC=true` (faster) |
| Bug bounty hunting | Default + review memory |
| Repeat scans of similar stack | Default (memory helps) |

---

## 🙏 Credits

Ghost Hacker is built on top of [Shannon](https://github.com/KeygraphHQ/shannon) by Keygraph. Shannon provides the core pentesting pipeline, Claude Agent SDK integration, and Temporal workflow infrastructure.

**Ghost Hacker adds:**
- Difficulty-based routing
- Adversarial dual-agent exploitation
- Collective memory system
- Enhanced CLI

---

## 📜 License

AGPL-3.0 (same as Shannon)

---

## ⚠️ Disclaimer

Ghost Hacker is for **authorized security testing only**. Only test systems you own or have explicit permission to test. The authors are not responsible for misuse.

---

<p align="center">
  <b>👻 Happy Hacking</b>
</p>
