# Achieving 96.15% Success on a Hint-Free, Source-Aware XBOW Benchmark

Ghost Hacker Lite, our open-source AI pentester, achieved a **96.15% success rate (100/104 exploits)** on a systematically cleaned, hint-free version of the XBOW security benchmark, running in a *white-box (source-available)* configuration.

For context, previously reported XBOW results for leading AI agents and expert human penetration testers achieved around 85% success on the original benchmark in *black-box mode*. Because Ghost Hacker was evaluated with full access to source code on a cleaned, hint-free variant, these results are not *apples-to-apples*, but they do highlight Ghost Hacker’s ability to perform deep, code-level reasoning in a realistic internal security review setting.

**Ghost Hacker Github:** [github.com/KeygraphHQ/ghosthacker](https://github.com/KeygraphHQ/ghosthacker)

**Cleaned Benchmark**: [xbow-validation-benchmarks](https://github.com/KeygraphHQ/xbow-validation-benchmarks)

**Benchmark Results, with detailed turn by turn agentic logs and full pentest report for each challenge**: [View Full Results](https://github.com/KeygraphHQ/ghosthacker/blob/main/xben-benchmark-results/)

![XBOW Performance Comparison](../assets/xbow-performance-comparison.png)

*Data sourced from: [XBOW](https://xbow.com/blog/xbow-vs-humans) and [Cyber-AutoAgent](https://medium.com/data-science-collective/building-the-leading-open-source-pentesting-agent-architecture-lessons-from-xbow-benchmark-f6874f932ca4)*

**About the benchmark:** XBOW is an open-source security benchmark containing 104 intentionally vulnerable applications designed to test AI agent capabilities on realistic penetration testing scenarios.

We tested against a fully cleaned, hint-free version of the benchmark in white-box mode, removing shortcuts like descriptive variable names, comments, and filenames that could artificially boost performance. This represents a more realistic evaluation of Ghost Hacker's core analysis and reasoning capabilities.

---

## Why This Matters: From Annual Audits to Continuous Security

Modern development teams ship code constantly. Your penetration test? That happens once a year, maybe twice if you're diligent. This creates a 364-day security gap where vulnerabilities can silently ship to production.

Ghost Hacker closes this gap by delivering autonomous, on-demand penetration testing with proof-based validation. It doesn't just flag potential issues, it executes real exploits to confirm vulnerabilities are actually exploitable.

**The shift in security economics:**

| **Metric** | **Traditional Pentest** | **Ghost Hacker** |
| --- | --- | --- |
| **Cost** | $10,000+ | ~$16 (API costs) |
| **Time** | Weeks to months, scheduled | Under 1.5 hours, on-demand |
| **Frequency** | 1-2x per year | Every deployment |

The 96.15% success rate on XBOW demonstrates that autonomous, continuous security testing is no longer theoretical, it's ready for real-world use.

---

## Performance Across Vulnerability Classes

Ghost Hacker demonstrated consistent performance across diverse attack vectors:

| **Vulnerability Type** | **Total Challenges** | **Succeeded** | **Success Rate** |
| --- | --- | --- | --- |
| Broken Authorization | 25 | 25 | 100% |
| SQL Injection | 7 | 7 | 100% |
| Blind SQL Injection | 3 | 3 | 100% |
| SSRF / Misconfiguration | 22 | 21 | 95.45% |
| XSS | 23 | 22 | 95.65% |
| Server-Side Template Injection | 13 | 12 | 92.31% |
| Command Injection | 11 | 10 | 90.91% |

This consistency reflects Ghost Hacker's structured, phase-based approach that maintains strategic coherence through complex, multi-step attack chains.

---

## Transparent Analysis: Our 4 Failures

Here is a detailed analysis of the 4 challenges Ghost Hacker did not solve. These failures highlight current limitations and define our roadmap.

- **XBEN-10 (XSS):**

    - **Diagnosis:** The agent correctly identified the vulnerability and character blacklist but incorrectly assessed the limitations of a JSFuck payload, abandoning a viable exploit path.

    - **Insight:** A knowledge gap exists in Ghost Hacker's payload encoding and obfuscation library.

- **XBEN-22 (SSTI/Default Credentials/Path Traversal):**

    - **Diagnosis:** While it successfully exploited 2 of the 3 vulnerabilities, the agent misclassified the Server-Side Template Injection (SSTI) vulnerability as a false positive and did not proceed with exploitation.

    - **Insight:** The agent's classification model for SSTI needs refinement to reduce false negatives.

- **XBEN-34 (RFI):**

    - **Diagnosis:** The agent correctly found the file inclusion vulnerability but misclassified it as Local File Inclusion (LFI) instead of Remote File Inclusion (RFI), leading it to attempt the wrong exploitation technique.

    - **Insight:** The classification logic between LFI and RFI must be improved based on server configuration analysis.

- **XBEN-82 (Command Injection via SSRF):**

    - **Diagnosis:** Ghost Hacker identified the full attack path but failed on two fronts: the analysis agent misclassified eval() as incapable of OS command execution, and the exploitation agent failed to initiate a local web server for the payload.

    - **Insight:** Agent capabilities need to be updated to correctly classify eval() risks and to utilize available local tooling for payload delivery.

---

## How Ghost Hacker Works: Proof by Exploitation

Ghost Hacker follows a structured, five-phase workflow designed to eliminate false positives:

```
    Reconnaissance → Vulnerability Analysis → Exploitation → Reporting
```

**The key difference:** Ghost Hacker doesn't stop at detection. Every reported vulnerability includes a working proof-of-concept exploit. If Ghost Hacker can't successfully exploit a vulnerability, it's not included in the report. No exploit = no report.

This "proof by exploitation" approach ensures every finding is:

- **Verified:** Confirmed through actual exploitation
- **Reproducible:** Includes copy-paste PoC code
- **Actionable:** Shows real impact, not theoretical risk

Ghost Hacker utilizes specialized agents for different vulnerability classes, running analysis and exploitation in parallel for efficiency. The system integrates industry-standard tools (Nmap, Subfinder, WhatWeb, Schemathesis) with custom browser automation and code analysis.

**For the complete technical breakdown,** see our article [Proof by Exploitation: Ghost Hacker's Approach to Autonomous Penetration Testing](https://medium.com/@parathan/proof-by-exploitation-ghosthackers-approach-to-autonomous-penetration-testing-010eac3588d3) and the [GitHub repository](https://github.com/KeygraphHQ/ghosthacker).

---

## What’s Next: Ghost Hacker Pro and Beyond

The 4 failures we analyzed above directly inform our immediate roadmap.

**[Ghost Hacker Pro](https://keygraph.io/ghosthacker) is coming:** While Ghost Hacker Lite uses a straightforward, context-window-based approach to code analysis, Ghost Hacker Pro will feature an advanced LLM-powered data flow analysis engine (inspired by the [LLMDFA paper](https://arxiv.org/abs/2402.10754)) that provides comprehensive, graph-based analysis of entire codebases, enabling detection of complex vulnerabilities that span multiple files and modules.

Ghost Hacker Pro will also bring enterprise-grade capabilities: production orchestration, dedicated support, and seamless integration into existing security and compliance workflows.

Beyond Ghost Hacker Pro, we're working toward a vision where security testing is as continuous as deployment:

- **Deeper coverage:** Expanding to additional OWASP categories and complex multi-step exploits
- **CI/CD integration:** Native support for automated testing in deployment pipelines
- **Faster iteration:** Optimizing for both thoroughness and speed

The 96.15% success rate on the XBOW benchmark demonstrates the feasibility. The next step is making autonomous pentesting a standard part of every development workflow.

Please fill out this form if you are interested in [Ghost Hacker Pro](https://docs.google.com/forms/d/e/1FAIpQLSf-cPZcWjlfBJ3TCT8AaWpf8ztsw3FaHzJE4urr55KdlQs6cQ/viewform?usp=header).

---

## Open Source Release: Benchmarks and Complete Results

We're releasing everything needed for independent validation:

**1. The Cleaned XBOW Benchmark**

- All 104 challenges with hints systematically removed
- Enables reproducible, unbiased agent evaluation
- **Available at:** [KeygraphHQ/xbow-validation-benchmarks](https://github.com/KeygraphHQ/xbow-validation-benchmarks)

**2. Complete Ghost Hacker Results Package**

- All 104 penetration testing reports
- Turn-by-turn agentic logs
- **Available in the same repository**

These resources record the benchmark configuration and complete results for all 104 challenges.

---

## Join the Community

- **GitHub:** [KeygraphHQ/ghosthacker](https://github.com/KeygraphHQ/ghosthacker)
- **Discord:** [Join our Discord](https://discord.gg/KAqzSHHpRt)
- **Twitter/X:** [@KeygraphHQ](https://x.com/KeygraphHQ)
- **Enterprise inquiries:** [ghosthacker@keygraph.io](mailto:ghosthacker@keygraph.io)

---

## Appendix: Methodology Notes

### Benchmark Cleaning Process

The original XBOW benchmark contains unintentional hints that can guide AI agents in white-box testing scenarios. To conduct a rigorous evaluation, we systematically removed hints from all 104 challenges:

- Descriptive variable names
- Source code comments
- Filepaths and filenames
- Application titles
- Dockerfile configurations

Ghost Hacker's 96.15% success rate was achieved exclusively on this cleaned version, representing a more realistic assessment of autonomous pentesting capabilities.

This cleaned benchmark is now available to the research community to establish a more rigorous standard for evaluating security agents.

### Adaptation for CTF-Style Testing

Ghost Hacker was originally designed as a generalist penetration testing system for complex, production applications. The XBOW benchmark consists of simpler, isolated CTF-style challenges.

Ghost Hacker's production-grade workflow includes comprehensive reconnaissance and vulnerability analysis phases that run regardless of target complexity. While this thoroughness is essential for real-world applications, it adds overhead on simpler CTF targets.

Additionally, Ghost Hacker's primary goal is exploit confirmation rather than CTF flag capture. A straightforward adaptation was made to extract flags when exploits succeeded, reflected in our public repository.

---

*Built with ❤️ by the Keygraph team*

*Making application security accessible to everyone*
