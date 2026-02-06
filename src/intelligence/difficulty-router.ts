// Adaptive Difficulty Router
// Analyze vulnerabilities BEFORE exploitation to route to optimal strategy

interface VulnerabilitySignal {
  id: string;
  type: 'sqli' | 'xss' | 'ssrf' | 'auth' | 'authz' | 'cmdi';
  endpoint: string;
  indicators: VulnIndicators;
}

interface VulnIndicators {
  // From code analysis
  hasParameterization: boolean;      // Prepared statements detected
  hasInputValidation: boolean;       // Regex/allowlist detected
  hasOutputEncoding: boolean;        // XSS protection
  hasWAF: boolean;                   // WAF middleware detected
  frameworkProtection: string[];     // e.g., ['rails_strong_params', 'django_orm']

  // From recon
  responsePatterns: ResponsePattern[];
  errorVerbosity: 'verbose' | 'generic' | 'silent';
  timingVariance: number;            // ms variance in responses

  // Contextual
  authRequired: boolean;
  dataClassification: 'public' | 'internal' | 'sensitive' | 'critical';
}

interface ResponsePattern {
  input: string;
  statusCode: number;
  bodyContains: string[];
  timingMs: number;
}

type DifficultyLevel = 'trivial' | 'standard' | 'hardened' | 'fortress';
type ExploitStrategy = 'quick_confirm' | 'methodical' | 'bypass_heavy' | 'research_mode';

interface RoutingDecision {
  vulnId: string;
  difficulty: DifficultyLevel;
  strategy: ExploitStrategy;
  estimatedAttempts: number;
  recommendedTools: string[];
  bypassTechniques: string[];
  skipReason?: string;
}

export class DifficultyRouter {

  /**
   * Analyze a vulnerability and determine optimal exploitation strategy
   */
  route(vuln: VulnerabilitySignal): RoutingDecision {
    const difficulty = this.assessDifficulty(vuln);
    const strategy = this.selectStrategy(difficulty, vuln);

    return {
      vulnId: vuln.id,
      difficulty,
      strategy: strategy.name,
      estimatedAttempts: strategy.attempts,
      recommendedTools: strategy.tools,
      bypassTechniques: strategy.bypasses,
      skipReason: strategy.skipReason
    };
  }

  private assessDifficulty(vuln: VulnerabilitySignal): DifficultyLevel {
    const { indicators } = vuln;
    let score = 0;

    // Defense layers add difficulty
    if (indicators.hasParameterization) score += 40;  // Big obstacle
    if (indicators.hasInputValidation) score += 20;
    if (indicators.hasOutputEncoding) score += 15;
    if (indicators.hasWAF) score += 25;

    // Framework protections
    score += indicators.frameworkProtection.length * 10;

    // Error handling affects exploitability
    if (indicators.errorVerbosity === 'silent') score += 15;
    if (indicators.errorVerbosity === 'generic') score += 5;

    // Map score to difficulty
    if (score >= 70) return 'fortress';
    if (score >= 40) return 'hardened';
    if (score >= 15) return 'standard';
    return 'trivial';
  }

  private selectStrategy(
    difficulty: DifficultyLevel,
    vuln: VulnerabilitySignal
  ): {
    name: ExploitStrategy;
    attempts: number;
    tools: string[];
    bypasses: string[];
    skipReason?: string;
  } {

    // Fortress-level with parameterization = likely false positive
    if (difficulty === 'fortress' && vuln.indicators.hasParameterization) {
      return {
        name: 'research_mode',
        attempts: 3,
        tools: ['code_review'],
        bypasses: [],
        skipReason: 'Parameterized queries detected - verify if vuln is real before heavy testing'
      };
    }

    switch (difficulty) {
      case 'trivial':
        return {
          name: 'quick_confirm',
          attempts: 5,
          tools: ['curl'],
          bypasses: []
        };

      case 'standard':
        return {
          name: 'methodical',
          attempts: 15,
          tools: ['curl', 'sqlmap'],
          bypasses: this.getBasicBypasses(vuln.type)
        };

      case 'hardened':
        return {
          name: 'bypass_heavy',
          attempts: 30,
          tools: ['curl', 'sqlmap', 'custom_scripts'],
          bypasses: this.getAdvancedBypasses(vuln.type, vuln.indicators)
        };

      case 'fortress':
        return {
          name: 'research_mode',
          attempts: 50,
          tools: ['curl', 'sqlmap', 'custom_scripts', 'burp_intruder'],
          bypasses: this.getAllBypasses(vuln.type)
        };
    }
  }

  private getBasicBypasses(type: VulnerabilitySignal['type']): string[] {
    const bypasses: Record<string, string[]> = {
      sqli: ['case_variation', 'inline_comments', 'url_encoding'],
      xss: ['case_variation', 'event_handlers', 'svg_vectors'],
      ssrf: ['ip_formats', 'dns_rebinding', 'protocol_smuggling'],
      cmdi: ['command_substitution', 'newline_injection', 'semicolon_chaining'],
      auth: ['timing_attacks', 'credential_stuffing'],
      authz: ['idor_fuzzing', 'header_manipulation']
    };
    return bypasses[type] || [];
  }

  private getAdvancedBypasses(
    type: VulnerabilitySignal['type'],
    indicators: VulnIndicators
  ): string[] {
    const basic = this.getBasicBypasses(type);

    const advanced: Record<string, string[]> = {
      sqli: [
        'double_encoding', 'null_byte_injection', 'unicode_normalization',
        'second_order', 'out_of_band_dns', 'time_based_blind'
      ],
      xss: [
        'polyglot_payloads', 'mutation_xss', 'dom_clobbering',
        'prototype_pollution', 'template_injection'
      ],
      ssrf: [
        'ipv6_bypass', 'url_parser_confusion', 'redirect_chains',
        'gopher_protocol', 'file_protocol'
      ],
      cmdi: [
        'environment_variables', 'glob_expansion', 'heredoc_injection',
        'ifs_manipulation'
      ],
      auth: ['jwt_confusion', 'oauth_redirect', 'session_fixation'],
      authz: ['mass_assignment', 'graphql_introspection', 'batch_operations']
    };

    // Add WAF-specific bypasses if WAF detected
    if (indicators.hasWAF) {
      basic.push(
        'chunked_encoding',
        'http_parameter_pollution',
        'multipart_boundary_confusion',
        'content_type_mismatch'
      );
    }

    return [...basic, ...(advanced[type] || [])];
  }

  private getAllBypasses(type: VulnerabilitySignal['type']): string[] {
    const indicators: VulnIndicators = {
      hasParameterization: false,
      hasInputValidation: true,
      hasOutputEncoding: true,
      hasWAF: true,
      frameworkProtection: [],
      responsePatterns: [],
      errorVerbosity: 'silent',
      timingVariance: 0,
      authRequired: false,
      dataClassification: 'critical'
    };
    return this.getAdvancedBypasses(type, indicators);
  }

  /**
   * Generate exploitation prompt tailored to the routing decision
   */
  generatePrompt(decision: RoutingDecision, basePrompt: string): string {
    const header = `## Routing Intelligence

**Difficulty Assessment:** ${decision.difficulty.toUpperCase()}
**Recommended Strategy:** ${decision.strategy}
**Estimated Attempts:** ${decision.estimatedAttempts}
**Primary Tools:** ${decision.recommendedTools.join(', ')}

${decision.skipReason ? `⚠️ **Note:** ${decision.skipReason}\n` : ''}

**Bypass Techniques to Prioritize:**
${decision.bypassTechniques.map(b => `- ${b}`).join('\n')}

---

`;

    // Inject strategy-specific instructions
    const strategyInstructions: Record<ExploitStrategy, string> = {
      quick_confirm: `
**QUICK CONFIRM MODE**
This looks like a straightforward vulnerability. Spend max 5 attempts:
1. Try the obvious payload first
2. If it works, document and move on
3. If blocked, escalate to methodical (request more context)
`,
      methodical: `
**METHODICAL MODE**
Standard vulnerability with some defenses. Follow the full OWASP workflow:
1. Confirm → 2. Fingerprint → 3. Enumerate → 4. Extract
Use sqlmap after 5 failed manual attempts.
`,
      bypass_heavy: `
**BYPASS HEAVY MODE**
Defenses detected. Prioritize bypass techniques over brute force:
1. Identify the specific blocking mechanism
2. Try bypasses in order of likelihood (see list above)
3. Use custom scripts for complex bypass chains
4. Document what's being blocked for the report
`,
      research_mode: `
**RESEARCH MODE**
This target has strong defenses. Before heavy testing:
1. Re-verify the vulnerability exists (code review found it but runtime might differ)
2. If parameterization is confirmed working, mark as FALSE POSITIVE early
3. Only proceed with exploitation if you find a genuine bypass
4. Time-box to 3 attempts - don't waste cycles on well-defended code
`
    };

    return header + strategyInstructions[decision.strategy] + '\n\n' + basePrompt;
  }
}

/**
 * Integration with Shannon's workflow
 */
export async function routeVulnerabilities(
  queueFile: string,
  preReconData: string,
  reconData: string
): Promise<Map<string, RoutingDecision>> {
  const router = new DifficultyRouter();
  const decisions = new Map<string, RoutingDecision>();

  // Parse queue (simplified - real impl would parse JSON)
  const vulns = parseVulnQueue(queueFile, preReconData, reconData);

  for (const vuln of vulns) {
    const decision = router.route(vuln);
    decisions.set(vuln.id, decision);

    // Log routing decision
    console.log(`[ROUTER] ${vuln.id}: ${decision.difficulty} → ${decision.strategy}`);
    if (decision.skipReason) {
      console.log(`         ⚠️ ${decision.skipReason}`);
    }
  }

  // Sort by difficulty - do easy ones first (quick wins)
  const sorted = [...decisions.entries()]
    .sort((a, b) => {
      const order: DifficultyLevel[] = ['trivial', 'standard', 'hardened', 'fortress'];
      return order.indexOf(a[1].difficulty) - order.indexOf(b[1].difficulty);
    });

  return new Map(sorted);
}

// Placeholder - real impl would parse actual files
function parseVulnQueue(
  _queueFile: string,
  _preReconData: string,
  _reconData: string
): VulnerabilitySignal[] {
  return [];
}

export { VulnerabilitySignal, RoutingDecision, DifficultyLevel, ExploitStrategy };