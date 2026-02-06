/**
 * Enhanced Activities for Adversarial Exploitation
 *
 * These activities power the enhanced workflow with:
 * - Difficulty routing
 * - Adversarial dual-agent exploitation
 * - Collective memory management
 */

import { Context } from '@temporalio/activity';
import { fs, path } from 'zx';
import chalk from 'chalk';

import { runClaudePrompt } from '../ai/claude-executor.js';
import { DifficultyRouter, type RoutingDecision, type VulnerabilitySignal } from '../intelligence/difficulty-router.js';
import {
  AdversarialExploitationOrchestrator,
  CollectiveMemory,
  CHAOS_AGENT,
  ORDER_AGENT,
  judgeResults
} from '../intelligence/adversarial-exploitation.js';
import type { AgentMetrics } from './shared.js';

// ============================================================================
// TYPES
// ============================================================================

interface EnhancedActivityInput {
  webUrl: string;
  repoPath: string;
  workflowId: string;
  configPath?: string;
  outputPath?: string;
  memoryPath?: string;
}

interface ExploitActivityInput extends EnhancedActivityInput {
  vulnId: string;
  strategy: string;
  techniques: string[];
}

interface AdversarialActivityInput extends EnhancedActivityInput {
  vulnId: string;
  difficulty: string;
  techniques: string[];
}

interface AdversarialActivityResult {
  winner: 'CHAOS' | 'ORDER' | 'TIE' | 'BOTH_FAILED';
  chaosSuccess: boolean;
  orderSuccess: boolean;
  lessons: string[];
  winnerMetrics?: AgentMetrics;
  memoryUpdates?: number;
}

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

const MEMORY_FILE = 'collective-memory.json';

async function loadMemory(repoPath: string): Promise<CollectiveMemory> {
  const memory = new CollectiveMemory();
  const memoryPath = path.join(repoPath, 'deliverables', MEMORY_FILE);

  try {
    if (await fs.exists(memoryPath)) {
      const data = await fs.readFile(memoryPath, 'utf-8');
      memory.import(data);
      console.log(chalk.blue(`[MEMORY] Loaded collective memory from ${memoryPath}`));
    }
  } catch (err) {
    console.log(chalk.yellow(`[MEMORY] Starting fresh - no previous memory found`));
  }

  return memory;
}

async function saveMemory(memory: CollectiveMemory, repoPath: string): Promise<void> {
  const memoryPath = path.join(repoPath, 'deliverables', MEMORY_FILE);

  try {
    await fs.ensureDir(path.dirname(memoryPath));
    await fs.writeFile(memoryPath, memory.export());
    console.log(chalk.green(`[MEMORY] Saved collective memory to ${memoryPath}`));
  } catch (err) {
    console.log(chalk.red(`[MEMORY] Failed to save: ${err}`));
  }
}

// ============================================================================
// ROUTING ACTIVITY
// ============================================================================

/**
 * Analyze vulnerabilities and route to optimal exploitation strategies
 */
export async function routeVulnerabilities(
  input: EnhancedActivityInput
): Promise<Record<string, RoutingDecision>> {
  Context.current().heartbeat('Starting vulnerability routing');
  console.log(chalk.cyan('\n[ROUTER] Analyzing vulnerability difficulty...'));

  const router = new DifficultyRouter();
  const decisions: Record<string, RoutingDecision> = {};

  // Read vulnerability queues from all vuln analysis phases
  const vulnTypes = ['injection', 'xss', 'auth', 'authz', 'ssrf'];
  const deliverablesPath = path.join(input.repoPath, 'deliverables');

  for (const vulnType of vulnTypes) {
    const queueFile = path.join(deliverablesPath, `${vulnType}_exploitation_queue.json`);

    if (await fs.exists(queueFile)) {
      try {
        const queueData = await fs.readFile(queueFile, 'utf-8');
        const queue = JSON.parse(queueData);

        // Parse each vulnerability in the queue
        for (const vuln of queue.vulnerabilities || []) {
          const signal: VulnerabilitySignal = {
            id: vuln.id || `${vulnType.toUpperCase()}-${Date.now()}`,
            type: vulnType as VulnerabilitySignal['type'],
            endpoint: vuln.endpoint || vuln.location || 'unknown',
            indicators: {
              hasParameterization: vuln.indicators?.parameterized || false,
              hasInputValidation: vuln.indicators?.validated || false,
              hasOutputEncoding: vuln.indicators?.encoded || false,
              hasWAF: vuln.indicators?.waf || false,
              frameworkProtection: vuln.indicators?.frameworks || [],
              responsePatterns: [],
              errorVerbosity: vuln.indicators?.errorVerbosity || 'generic',
              timingVariance: 0,
              authRequired: vuln.requiresAuth || false,
              dataClassification: vuln.dataClassification || 'internal'
            }
          };

          const decision = router.route(signal);
          decisions[signal.id] = decision;

          console.log(chalk.gray(
            `  ${signal.id}: ${decision.difficulty} → ${decision.strategy} ` +
            `(${decision.estimatedAttempts} attempts)`
          ));
        }
      } catch (err) {
        console.log(chalk.yellow(`  Skipping ${vulnType}: ${err}`));
      }
    }

    Context.current().heartbeat(`Routed ${vulnType} vulnerabilities`);
  }

  const total = Object.keys(decisions).length;
  const byDifficulty = {
    trivial: Object.values(decisions).filter(d => d.difficulty === 'trivial').length,
    standard: Object.values(decisions).filter(d => d.difficulty === 'standard').length,
    hardened: Object.values(decisions).filter(d => d.difficulty === 'hardened').length,
    fortress: Object.values(decisions).filter(d => d.difficulty === 'fortress').length
  };

  console.log(chalk.cyan(`\n[ROUTER] Routing complete:`));
  console.log(chalk.gray(`  Total: ${total} vulnerabilities`));
  console.log(chalk.green(`  Trivial: ${byDifficulty.trivial}`));
  console.log(chalk.blue(`  Standard: ${byDifficulty.standard}`));
  console.log(chalk.yellow(`  Hardened: ${byDifficulty.hardened}`));
  console.log(chalk.red(`  Fortress: ${byDifficulty.fortress}`));

  return decisions;
}

// ============================================================================
// SINGLE AGENT EXPLOIT ACTIVITY
// ============================================================================

/**
 * Run a single exploit agent with strategy-specific prompt modifications
 */
export async function runExploitAgent(
  input: ExploitActivityInput
): Promise<AgentMetrics> {
  const startTime = Date.now();
  Context.current().heartbeat(`Starting exploit for ${input.vulnId}`);

  console.log(chalk.cyan(`\n[EXPLOIT] ${input.vulnId} (${input.strategy})`));

  // Load base prompt for the vuln type
  const vulnType = input.vulnId.split('-')[0].toLowerCase();
  const promptPath = path.join(process.cwd(), 'prompts', `exploit-${vulnType}.txt`);

  let basePrompt = '';
  try {
    basePrompt = await fs.readFile(promptPath, 'utf-8');
  } catch {
    basePrompt = getDefaultExploitPrompt(vulnType);
  }

  // Inject routing intelligence
  const routingContext = `
## ROUTING INTELLIGENCE

**Vulnerability ID:** ${input.vulnId}
**Strategy:** ${input.strategy}
**Recommended Techniques:**
${input.techniques.map((t, i) => `${i + 1}. ${t}`).join('\n')}

**Strategy Instructions:**
${getStrategyInstructions(input.strategy)}

---

`;

  const enhancedPrompt = routingContext + basePrompt;

  // Run the agent
  const result = await runClaudePrompt(
    enhancedPrompt,
    input.repoPath,
    `Target: ${input.webUrl}\nVulnerability: ${input.vulnId}`,
    `Exploit ${input.vulnId}`,
    `${vulnType}-exploit`,
    chalk.red
  );

  Context.current().heartbeat(`Completed exploit for ${input.vulnId}`);

  return {
    durationMs: Date.now() - startTime,
    costUsd: result.cost,
    numTurns: result.turns || 0,
    success: result.success
  };
}

// ============================================================================
// ADVERSARIAL EXPLOIT ACTIVITY
// ============================================================================

/**
 * Run adversarial dual-agent exploitation (CHAOS vs ORDER)
 */
export async function runAdversarialExploit(
  input: AdversarialActivityInput
): Promise<AdversarialActivityResult> {
  const startTime = Date.now();
  Context.current().heartbeat(`Starting adversarial exploit for ${input.vulnId}`);

  console.log(chalk.magenta(`\n[ADVERSARIAL] ⚔️  CHAOS vs ORDER: ${input.vulnId}`));
  console.log(chalk.gray(`  Difficulty: ${input.difficulty}`));

  // Load collective memory
  const memory = await loadMemory(input.repoPath);

  // Determine tech stack from recon data
  const techStack = await detectTechStack(input.repoPath);
  console.log(chalk.gray(`  Tech stack: ${techStack.framework}/${techStack.database}`));

  // Get memory-informed recommendations
  const vulnType = input.vulnId.split('-')[0].toLowerCase();
  const chaosRecs = CHAOS_AGENT.techniqueSelector(memory, techStack, vulnType);
  const orderRecs = ORDER_AGENT.techniqueSelector(memory, techStack, vulnType);

  console.log(chalk.red(`  CHAOS will try: ${chaosRecs.slice(0, 3).join(', ')}...`));
  console.log(chalk.blue(`  ORDER will try: ${orderRecs.slice(0, 3).join(', ')}...`));

  // Load base prompt
  const promptPath = path.join(process.cwd(), 'prompts', `exploit-${vulnType}.txt`);
  let basePrompt = '';
  try {
    basePrompt = await fs.readFile(promptPath, 'utf-8');
  } catch {
    basePrompt = getDefaultExploitPrompt(vulnType);
  }

  // Build agent-specific prompts
  const chaosPrompt = CHAOS_AGENT.promptModifier + buildTechniqueSection(chaosRecs) + basePrompt;
  const orderPrompt = ORDER_AGENT.promptModifier + buildTechniqueSection(orderRecs) + basePrompt;

  // Run both agents in parallel
  Context.current().heartbeat('Running CHAOS agent');
  const chaosPromise = runClaudePrompt(
    chaosPrompt,
    input.repoPath,
    `Target: ${input.webUrl}\nVulnerability: ${input.vulnId}`,
    `CHAOS Exploit ${input.vulnId}`,
    `${vulnType}-exploit`,
    chalk.red
  );

  Context.current().heartbeat('Running ORDER agent');
  const orderPromise = runClaudePrompt(
    orderPrompt,
    input.repoPath,
    `Target: ${input.webUrl}\nVulnerability: ${input.vulnId}`,
    `ORDER Exploit ${input.vulnId}`,
    `${vulnType}-exploit`,
    chalk.blue
  );

  const [chaosResult, orderResult] = await Promise.all([chaosPromise, orderPromise]);

  // Judge the results
  const chaosExploitResult = {
    agent: 'CHAOS',
    vulnId: input.vulnId,
    success: chaosResult.success && !chaosResult.error,
    evidence: chaosResult.result || '',
    techniques: chaosRecs,
    timeMs: chaosResult.duration,
    attempts: chaosResult.turns || 0
  };

  const orderExploitResult = {
    agent: 'ORDER',
    vulnId: input.vulnId,
    success: orderResult.success && !orderResult.error,
    evidence: orderResult.result || '',
    techniques: orderRecs,
    timeMs: orderResult.duration,
    attempts: orderResult.turns || 0
  };

  const judgement = judgeResults(chaosExploitResult, orderExploitResult);

  // Log results
  console.log(chalk.magenta(`\n[JUDGE] 🏆 Winner: ${judgement.winner}`));
  console.log(chalk.gray(`  Reasoning: ${judgement.reasoning}`));

  if (judgement.lessonsLearned.length > 0) {
    console.log(chalk.yellow(`  Lessons learned:`));
    for (const lesson of judgement.lessonsLearned) {
      console.log(chalk.gray(`    • ${lesson}`));
    }
  }

  // Update collective memory
  for (const update of judgement.memoryUpdates) {
    update.vulnType = vulnType;
    update.techStack = techStack;
    memory.record(update);
  }

  // Save memory
  await saveMemory(memory, input.repoPath);

  Context.current().heartbeat(`Completed adversarial exploit for ${input.vulnId}`);

  // Determine winner's metrics
  let winnerMetrics: AgentMetrics | undefined;
  if (judgement.winner === 'CHAOS') {
    winnerMetrics = {
      durationMs: chaosResult.duration,
      costUsd: chaosResult.cost,
      numTurns: chaosResult.turns || 0,
      success: true
    };
  } else if (judgement.winner === 'ORDER') {
    winnerMetrics = {
      durationMs: orderResult.duration,
      costUsd: orderResult.cost,
      numTurns: orderResult.turns || 0,
      success: true
    };
  }

  return {
    winner: judgement.winner,
    chaosSuccess: chaosExploitResult.success,
    orderSuccess: orderExploitResult.success,
    lessons: judgement.lessonsLearned,
    winnerMetrics,
    memoryUpdates: judgement.memoryUpdates.length
  };
}

// ============================================================================
// ENHANCED REPORT ACTIVITY
// ============================================================================

interface EnhancedReportInput extends EnhancedActivityInput {
  adversarialResults: Array<{
    vulnId: string;
    winner: string;
    chaosSucceeded: boolean;
    orderSucceeded: boolean;
    lessonsLearned: string[];
  }>;
  routingDecisions: Record<string, RoutingDecision>;
  memoryUpdates: number;
}

/**
 * Generate enhanced report with adversarial insights
 */
export async function runEnhancedReportAgent(
  input: EnhancedReportInput
): Promise<AgentMetrics> {
  const startTime = Date.now();
  Context.current().heartbeat('Generating enhanced report');

  console.log(chalk.cyan('\n[REPORT] Generating enhanced security report...'));

  // Build adversarial insights section
  let adversarialSection = '';
  if (input.adversarialResults && input.adversarialResults.length > 0) {
    const chaosWins = input.adversarialResults.filter(r => r.winner === 'CHAOS').length;
    const orderWins = input.adversarialResults.filter(r => r.winner === 'ORDER').length;

    adversarialSection = `
## Adversarial Exploitation Insights

This assessment used dual-agent adversarial testing on ${input.adversarialResults.length} hardened targets.

**Battle Results:**
- CHAOS Agent Wins: ${chaosWins}
- ORDER Agent Wins: ${orderWins}
- Ties: ${input.adversarialResults.filter(r => r.winner === 'TIE').length}
- Both Failed: ${input.adversarialResults.filter(r => r.winner === 'BOTH_FAILED').length}

**Key Lessons Learned:**
${input.adversarialResults
  .flatMap(r => r.lessonsLearned)
  .filter((v, i, a) => a.indexOf(v) === i)  // unique
  .map(l => `- ${l}`)
  .join('\n')}

**Collective Memory Updates:** ${input.memoryUpdates} new techniques recorded for future scans.

`;
  }

  // Build routing insights
  let routingSection = '';
  if (input.routingDecisions && Object.keys(input.routingDecisions).length > 0) {
    const decisions = Object.values(input.routingDecisions);
    routingSection = `
## Vulnerability Difficulty Analysis

| Difficulty | Count | Strategy |
|------------|-------|----------|
| Trivial | ${decisions.filter(d => d.difficulty === 'trivial').length} | Quick confirm |
| Standard | ${decisions.filter(d => d.difficulty === 'standard').length} | Methodical |
| Hardened | ${decisions.filter(d => d.difficulty === 'hardened').length} | Bypass-heavy |
| Fortress | ${decisions.filter(d => d.difficulty === 'fortress').length} | Adversarial |

`;
  }

  // Load base report prompt
  const promptPath = path.join(process.cwd(), 'prompts', 'report-executive.txt');
  let basePrompt = '';
  try {
    basePrompt = await fs.readFile(promptPath, 'utf-8');
  } catch {
    basePrompt = 'Generate a comprehensive security assessment report based on the exploitation evidence in deliverables/.';
  }

  const enhancedContext = `
## Additional Report Sections

Include these sections in the final report:

${adversarialSection}
${routingSection}

---

`;

  const result = await runClaudePrompt(
    basePrompt,
    input.repoPath,
    enhancedContext + `Target: ${input.webUrl}`,
    'Enhanced Security Report',
    'report',
    chalk.green
  );

  Context.current().heartbeat('Report generation complete');

  return {
    durationMs: Date.now() - startTime,
    costUsd: result.cost,
    numTurns: result.turns || 0,
    success: result.success
  };
}

// ============================================================================
// HELPERS
// ============================================================================

function getStrategyInstructions(strategy: string): string {
  const instructions: Record<string, string> = {
    quick_confirm: `
QUICK CONFIRM MODE - Max 5 attempts
1. Try the obvious payload first
2. If it works, document and move on
3. If blocked after 3 attempts, mark as needs-escalation`,

    methodical: `
METHODICAL MODE - Follow OWASP workflow
1. Confirm → 2. Fingerprint → 3. Enumerate → 4. Extract
Use automated tools after 5 failed manual attempts`,

    bypass_heavy: `
BYPASS HEAVY MODE - Focus on evasion
1. Identify the specific blocking mechanism
2. Try bypass techniques in priority order
3. Use custom scripts for complex bypass chains
4. Document what's being blocked`,

    research_mode: `
RESEARCH MODE - Verify before heavy testing
1. Re-verify the vulnerability exists in runtime
2. If defenses are solid, mark as false positive early
3. Only proceed if you find a genuine bypass
4. Time-box to 5 attempts max`
  };

  return instructions[strategy] || instructions.methodical;
}

function getDefaultExploitPrompt(vulnType: string): string {
  return `
You are an exploitation specialist. Your goal is to prove the ${vulnType} vulnerability is exploitable.

For each vulnerability:
1. Confirm the injection point exists
2. Extract data to prove exploitability
3. Document with reproducible commands

Save your evidence using the save_deliverable MCP tool with type "${vulnType.toUpperCase()}_EVIDENCE".
`;
}

function buildTechniqueSection(techniques: string[]): string {
  return `
## Recommended Techniques (from collective memory)
${techniques.map((t, i) => `${i + 1}. ${t}`).join('\n')}

Try these in priority order, but adapt based on responses.

---

`;
}

async function detectTechStack(repoPath: string): Promise<{
  language: string;
  framework: string;
  database: string;
  waf: string | null;
}> {
  // Try to read from pre-recon deliverable
  const preReconPath = path.join(repoPath, 'deliverables', 'pre_recon_deliverable.md');

  try {
    if (await fs.exists(preReconPath)) {
      const content = await fs.readFile(preReconPath, 'utf-8');

      // Simple pattern matching - real impl would be smarter
      const language = content.match(/language[:\s]*(python|node|java|ruby|php|go)/i)?.[1] || 'unknown';
      const framework = content.match(/framework[:\s]*(express|django|spring|rails|laravel|flask|fastapi)/i)?.[1] || 'unknown';
      const database = content.match(/database[:\s]*(mysql|postgres|mongodb|sqlite|mssql|oracle)/i)?.[1] || 'unknown';
      const waf = content.match(/waf[:\s]*(cloudflare|modsecurity|aws\s*waf|akamai)/i)?.[1] || null;

      return { language, framework, database, waf };
    }
  } catch {
    // Fall through to defaults
  }

  return {
    language: 'unknown',
    framework: 'unknown',
    database: 'unknown',
    waf: null
  };
}

// Export for worker registration
export const enhancedActivities = {
  routeVulnerabilities,
  runExploitAgent,
  runAdversarialExploit,
  runEnhancedReportAgent
};