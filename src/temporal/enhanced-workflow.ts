/**
 * Enhanced Ghost Hacker Workflow
 *
 * Integrates three innovations:
 * 1. Difficulty Router - Route vulns to optimal strategies before exploitation
 * 2. Adversarial Agents - CHAOS vs ORDER compete on hardened targets
 * 3. Collective Memory - Learn from past scans across all targets
 *
 * The workflow dynamically decides:
 * - Trivial vulns → Single agent, quick confirm
 * - Standard vulns → Single agent, methodical
 * - Hardened vulns → Adversarial dual-agent
 * - Fortress vulns → Adversarial + extended timeout
 */

import {
  proxyActivities,
  setHandler,
  workflowInfo,
} from '@temporalio/workflow';
import type * as activities from './activities.js';
import {
  getProgress,
  type PipelineInput,
  type PipelineState,
  type AgentMetrics,
} from './shared.js';
import type { DifficultyLevel, RoutingDecision } from '../intelligence/difficulty-router.js';

// Activity proxies with different timeouts based on difficulty
const quickActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '30 minutes',
  heartbeatTimeout: '5 minutes',
  retry: { maximumAttempts: 3 }
});

const standardActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '2 hours',
  heartbeatTimeout: '10 minutes',
  retry: { maximumAttempts: 10 }
});

const adversarialActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '4 hours',  // Longer for dual-agent
  heartbeatTimeout: '15 minutes',
  retry: { maximumAttempts: 20 }
});

interface EnhancedPipelineInput extends PipelineInput {
  enableAdversarial?: boolean;      // Use dual-agent on hard targets
  memoryPath?: string;               // Path to collective memory
  difficultyOverride?: DifficultyLevel;  // Force a difficulty level
}

interface EnhancedPipelineState extends PipelineState {
  routingDecisions: Map<string, RoutingDecision>;
  adversarialResults: AdversarialVulnResult[];
  memoryUpdates: number;
}

interface AdversarialVulnResult {
  vulnId: string;
  winner: 'CHAOS' | 'ORDER' | 'TIE' | 'BOTH_FAILED';
  chaosSucceeded: boolean;
  orderSucceeded: boolean;
  lessonsLearned: string[];
}

export async function enhancedPentestWorkflow(
  input: EnhancedPipelineInput
): Promise<EnhancedPipelineState> {
  const { workflowId } = workflowInfo();

  const state: EnhancedPipelineState = {
    status: 'running',
    currentPhase: null,
    currentAgent: null,
    completedAgents: [],
    failedAgent: null,
    error: null,
    startTime: Date.now(),
    agentMetrics: {},
    summary: null,
    routingDecisions: new Map(),
    adversarialResults: [],
    memoryUpdates: 0
  };

  // Register query handler
  setHandler(getProgress, () => ({
    ...state,
    workflowId,
    elapsedMs: Date.now() - state.startTime,
    // Include enhanced stats
    adversarialWins: {
      chaos: state.adversarialResults.filter(r => r.winner === 'CHAOS').length,
      order: state.adversarialResults.filter(r => r.winner === 'ORDER').length,
      tie: state.adversarialResults.filter(r => r.winner === 'TIE').length
    }
  }));

  const activityInput = {
    webUrl: input.webUrl,
    repoPath: input.repoPath,
    workflowId,
    configPath: input.configPath,
    outputPath: input.outputPath,
    memoryPath: input.memoryPath
  };

  try {
    // ========================================================================
    // Phase 1-2: Pre-Recon & Recon (unchanged)
    // ========================================================================
    state.currentPhase = 'pre-recon';
    state.agentMetrics['pre-recon'] = await standardActs.runPreReconAgent(activityInput);
    state.completedAgents.push('pre-recon');

    state.currentPhase = 'recon';
    state.agentMetrics['recon'] = await standardActs.runReconAgent(activityInput);
    state.completedAgents.push('recon');

    // ========================================================================
    // NEW: Route vulnerabilities based on difficulty
    // ========================================================================
    state.currentPhase = 'routing';
    console.log('[ENHANCED] Analyzing vulnerability difficulty...');

    const routingResults = await standardActs.routeVulnerabilities(activityInput);

    for (const [vulnId, decision] of Object.entries(routingResults)) {
      state.routingDecisions.set(vulnId, decision as RoutingDecision);
      console.log(`[ROUTER] ${vulnId}: ${(decision as RoutingDecision).difficulty} → ${(decision as RoutingDecision).strategy}`);
    }

    // Group vulnerabilities by difficulty
    const vulnsByDifficulty = groupByDifficulty(state.routingDecisions);

    // ========================================================================
    // Phase 3-4: Adaptive Exploitation
    // ========================================================================
    state.currentPhase = 'exploitation';

    // Trivial & Standard: Single agent, run in parallel
    const singleAgentVulns = [
      ...vulnsByDifficulty.trivial,
      ...vulnsByDifficulty.standard
    ];

    if (singleAgentVulns.length > 0) {
      console.log(`[ENHANCED] Running single-agent exploitation on ${singleAgentVulns.length} vulns`);

      const singleAgentResults = await Promise.allSettled(
        singleAgentVulns.map(async (decision) => {
          const acts = decision.difficulty === 'trivial' ? quickActs : standardActs;
          return acts.runExploitAgent({
            ...activityInput,
            vulnId: decision.vulnId,
            strategy: decision.strategy,
            techniques: decision.bypassTechniques
          });
        })
      );

      // Record results
      for (let i = 0; i < singleAgentResults.length; i++) {
        const result = singleAgentResults[i];
        const vulnId = singleAgentVulns[i].vulnId;

        if (result.status === 'fulfilled') {
          state.agentMetrics[`exploit-${vulnId}`] = result.value;
          state.completedAgents.push(`exploit-${vulnId}`);
        }
      }
    }

    // Hardened & Fortress: Adversarial dual-agent (if enabled)
    const adversarialVulns = [
      ...vulnsByDifficulty.hardened,
      ...vulnsByDifficulty.fortress
    ];

    if (adversarialVulns.length > 0 && input.enableAdversarial) {
      console.log(`[ENHANCED] Running ADVERSARIAL exploitation on ${adversarialVulns.length} vulns`);

      // Run adversarial vulns sequentially (resource intensive)
      for (const decision of adversarialVulns) {
        console.log(`\n[ADVERSARIAL] Dual-agent battle for ${decision.vulnId}`);

        const result = await adversarialActs.runAdversarialExploit({
          ...activityInput,
          vulnId: decision.vulnId,
          difficulty: decision.difficulty,
          techniques: decision.bypassTechniques
        });

        state.adversarialResults.push({
          vulnId: decision.vulnId,
          winner: result.winner,
          chaosSucceeded: result.chaosSuccess,
          orderSucceeded: result.orderSuccess,
          lessonsLearned: result.lessons
        });

        // Track the winner's metrics
        if (result.winnerMetrics) {
          state.agentMetrics[`adversarial-${decision.vulnId}`] = result.winnerMetrics;
        }

        state.completedAgents.push(`adversarial-${decision.vulnId}`);
        state.memoryUpdates += result.memoryUpdates || 0;
      }

      // Log adversarial summary
      const chaosWins = state.adversarialResults.filter(r => r.winner === 'CHAOS').length;
      const orderWins = state.adversarialResults.filter(r => r.winner === 'ORDER').length;
      console.log(`\n[ADVERSARIAL SUMMARY] CHAOS: ${chaosWins} | ORDER: ${orderWins}`);

    } else if (adversarialVulns.length > 0) {
      // Adversarial disabled - fall back to single agent with extended timeout
      console.log(`[ENHANCED] Adversarial disabled - using methodical approach on ${adversarialVulns.length} hard vulns`);

      for (const decision of adversarialVulns) {
        const result = await adversarialActs.runExploitAgent({
          ...activityInput,
          vulnId: decision.vulnId,
          strategy: 'bypass_heavy',
          techniques: decision.bypassTechniques
        });

        state.agentMetrics[`exploit-${decision.vulnId}`] = result;
        state.completedAgents.push(`exploit-${decision.vulnId}`);
      }
    }

    // ========================================================================
    // Phase 5: Enhanced Reporting
    // ========================================================================
    state.currentPhase = 'reporting';

    // Include adversarial insights in the report
    const reportContext = {
      ...activityInput,
      adversarialResults: state.adversarialResults,
      routingDecisions: Object.fromEntries(state.routingDecisions),
      memoryUpdates: state.memoryUpdates
    };

    state.agentMetrics['report'] = await standardActs.runEnhancedReportAgent(reportContext);
    state.completedAgents.push('report');

    // ========================================================================
    // Complete
    // ========================================================================
    state.status = 'completed';
    state.currentPhase = null;

    // Log final stats
    console.log('\n[ENHANCED WORKFLOW COMPLETE]');
    console.log(`  Total vulns processed: ${state.routingDecisions.size}`);
    console.log(`  Adversarial battles: ${state.adversarialResults.length}`);
    console.log(`  Memory updates: ${state.memoryUpdates}`);
    console.log(`  Duration: ${Math.round((Date.now() - state.startTime) / 1000 / 60)} minutes`);

    return state;

  } catch (error) {
    state.status = 'failed';
    state.failedAgent = state.currentAgent;
    state.error = error instanceof Error ? error.message : String(error);
    throw error;
  }
}

// Helper to group vulnerabilities by difficulty
function groupByDifficulty(
  decisions: Map<string, RoutingDecision>
): Record<DifficultyLevel, RoutingDecision[]> {
  const groups: Record<DifficultyLevel, RoutingDecision[]> = {
    trivial: [],
    standard: [],
    hardened: [],
    fortress: []
  };

  for (const decision of decisions.values()) {
    groups[decision.difficulty].push(decision);
  }

  return groups;
}

// Type for adversarial result from activity
interface AdversarialActivityResult {
  winner: 'CHAOS' | 'ORDER' | 'TIE' | 'BOTH_FAILED';
  chaosSuccess: boolean;
  orderSuccess: boolean;
  lessons: string[];
  winnerMetrics?: AgentMetrics;
  memoryUpdates?: number;
}

// Declare additional activity types
declare module './activities.js' {
  export function routeVulnerabilities(input: unknown): Promise<Record<string, RoutingDecision>>;
  export function runExploitAgent(input: unknown): Promise<AgentMetrics>;
  export function runAdversarialExploit(input: unknown): Promise<AdversarialActivityResult>;
  export function runEnhancedReportAgent(input: unknown): Promise<AgentMetrics>;
}