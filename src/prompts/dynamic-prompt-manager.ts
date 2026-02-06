// Dynamic Prompt Escalation System
// Start minimal, escalate complexity only when needed

interface EscalationLevel {
  level: number;
  name: string;
  sections: string[];
  triggerAfterAttempts: number;
}

interface PromptComponent {
  id: string;
  content: string;
  level: number;  // 1 = always include, 2+ = escalation only
  category: 'role' | 'objective' | 'methodology' | 'techniques' | 'edge_cases';
}

const ESCALATION_LEVELS: EscalationLevel[] = [
  {
    level: 1,
    name: 'minimal',
    sections: ['role', 'objective'],
    triggerAfterAttempts: 0
  },
  {
    level: 2,
    name: 'standard',
    sections: ['role', 'objective', 'methodology'],
    triggerAfterAttempts: 5
  },
  {
    level: 3,
    name: 'comprehensive',
    sections: ['role', 'objective', 'methodology', 'techniques'],
    triggerAfterAttempts: 10
  },
  {
    level: 4,
    name: 'exhaustive',
    sections: ['role', 'objective', 'methodology', 'techniques', 'edge_cases'],
    triggerAfterAttempts: 15
  }
];

// Injection prompt broken into components
const INJECTION_COMPONENTS: PromptComponent[] = [
  {
    id: 'role',
    level: 1,
    category: 'role',
    content: `You are an Injection Exploitation Specialist. Your goal is to prove SQL/Command injection vulnerabilities are exploitable by extracting actual data.`
  },
  {
    id: 'objective',
    level: 1,
    category: 'objective',
    content: `For each vulnerability in deliverables/injection_exploitation_queue.json:
1. Confirm the injection point exists
2. Extract data to prove exploitability
3. Document with reproducible commands

Success = actual data extracted. Theory without proof = failure.`
  },
  {
    id: 'methodology_basic',
    level: 2,
    category: 'methodology',
    content: `## Methodology
1. Read the queue file
2. For each vuln: probe → confirm → enumerate → extract
3. Use curl for manual testing, sqlmap for automation
4. Save evidence via save_deliverable MCP tool`
  },
  {
    id: 'methodology_workflow',
    level: 2,
    category: 'methodology',
    content: `## OWASP Workflow
Stage 1: Confirm (error messages, timing, boolean responses)
Stage 2: Fingerprint (DB version, user, tables)
Stage 3: Extract (first 5 rows from sensitive table)

Must reach Stage 3 with actual data to mark EXPLOITED.`
  },
  {
    id: 'techniques_basic',
    level: 3,
    category: 'techniques',
    content: `## Techniques
- UNION-based: ' UNION SELECT NULL,NULL,NULL--
- Error-based: ' AND 1=CONVERT(int,@@version)--
- Boolean blind: ' AND 1=1-- vs ' AND 1=2--
- Time blind: ' AND SLEEP(5)--`
  },
  {
    id: 'techniques_bypass',
    level: 3,
    category: 'techniques',
    content: `## WAF Bypass Techniques
- Case variation: uNiOn SeLeCt
- Inline comments: UN/**/ION SEL/**/ECT
- URL encoding: %55%4e%49%4f%4e
- Double encoding: %2555%254e%2549%254f%254e
- Null bytes: %00' UNION SELECT`
  },
  {
    id: 'edge_cases',
    level: 4,
    category: 'edge_cases',
    content: `## Edge Cases & Advanced
- Second-order injection (stored then triggered)
- Out-of-band via DNS/HTTP exfil
- Stacked queries if supported
- JSON/XML injection in nested params
- Header injection (X-Forwarded-For, Referer)
- Cookie-based injection points`
  },
  {
    id: 'classification',
    level: 4,
    category: 'edge_cases',
    content: `## Classification Rules
EXPLOITED: Data extracted, reproducible commands documented
POTENTIAL: Confirmed vuln but blocked by external factor (not WAF)
FALSE POSITIVE: WAF successfully blocked after 10+ bypass attempts

WAF blocking = try bypasses first, not automatic false positive.`
  }
];

export class DynamicPromptManager {
  private components: PromptComponent[];
  private currentLevel: number = 1;
  private attemptCount: number = 0;

  constructor(components: PromptComponent[] = INJECTION_COMPONENTS) {
    this.components = components;
  }

  /**
   * Get prompt for current escalation level
   */
  getPrompt(context: { targetUrl: string; queueFile: string }): string {
    const level = ESCALATION_LEVELS.find(l => l.level === this.currentLevel)!;

    const includedComponents = this.components
      .filter(c => c.level <= this.currentLevel)
      .sort((a, b) => {
        const order = ['role', 'objective', 'methodology', 'techniques', 'edge_cases'];
        return order.indexOf(a.category) - order.indexOf(b.category);
      });

    const prompt = includedComponents.map(c => c.content).join('\n\n');

    const header = `[Escalation Level ${this.currentLevel}/${ESCALATION_LEVELS.length}: ${level.name}]
Target: ${context.targetUrl}
Queue: ${context.queueFile}

`;

    return header + prompt;
  }

  /**
   * Record an attempt and check if we should escalate
   */
  recordAttempt(success: boolean): { escalated: boolean; newLevel: number } {
    this.attemptCount++;

    if (success) {
      return { escalated: false, newLevel: this.currentLevel };
    }

    const nextLevel = ESCALATION_LEVELS.find(
      l => l.level > this.currentLevel && l.triggerAfterAttempts <= this.attemptCount
    );

    if (nextLevel) {
      this.currentLevel = nextLevel.level;
      return { escalated: true, newLevel: this.currentLevel };
    }

    return { escalated: false, newLevel: this.currentLevel };
  }

  /**
   * Get token estimate for current prompt
   */
  estimateTokens(): number {
    const prompt = this.getPrompt({ targetUrl: '', queueFile: '' });
    // Rough estimate: 4 chars per token
    return Math.ceil(prompt.length / 4);
  }

  /**
   * Compare token usage across levels
   */
  static compareTokenUsage(): void {
    const manager = new DynamicPromptManager();

    console.log('Token usage by escalation level:');
    for (const level of ESCALATION_LEVELS) {
      manager.currentLevel = level.level;
      const tokens = manager.estimateTokens();
      console.log(`  Level ${level.level} (${level.name}): ~${tokens} tokens`);
    }
  }
}

// Export for testing
export { ESCALATION_LEVELS, INJECTION_COMPONENTS };