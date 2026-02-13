// Copyright (C) 2026 Ghost Hacker Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Oracle Probe MCP Tool
 *
 * Supports blind injection exploitation by providing structured
 * oracle probe tracking. The agent sends boolean questions to the
 * target and this tool helps track the binary search state,
 * timing measurements, and extraction progress.
 */

import { tool } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';
import { createToolResult, type ToolResult } from '../types/tool-responses.js';

// Track oracle probe state across calls
interface OracleState {
  probeCount: number;
  trueCount: number;
  falseCount: number;
  errorCount: number;
  extractedData: string;
  avgResponseMs: number;
  baselineMs: number | null;
  dbType: string | null;
  startedAt: number;
}

const oracleStates = new Map<string, OracleState>();

function getOrCreateState(sessionId: string): OracleState {
  if (!oracleStates.has(sessionId)) {
    oracleStates.set(sessionId, {
      probeCount: 0,
      trueCount: 0,
      falseCount: 0,
      errorCount: 0,
      extractedData: '',
      avgResponseMs: 0,
      baselineMs: null,
      dbType: null,
      startedAt: Date.now(),
    });
  }
  return oracleStates.get(sessionId)!;
}

const OracleProbeSchema = z.object({
  session_id: z.string().describe('Unique session ID for this blind injection extraction (use scan_id + endpoint)'),
  probe_type: z.enum(['boolean', 'time', 'error']).describe('Type of oracle: boolean (page diff), time (delay measurement), error (error message diff)'),
  result: z.enum(['true', 'false', 'error', 'timeout']).describe('Result of the oracle probe'),
  response_time_ms: z.number().optional().describe('Response time in milliseconds (critical for time-based probes)'),
  payload_used: z.string().describe('The exact payload sent for this probe'),
  extracted_char: z.string().optional().describe('Character extracted from this probe (if binary search completed for this position)'),
  position: z.number().optional().describe('Character position being extracted (0-indexed)'),
  db_type: z.string().optional().describe('Database type if identified: mysql, postgresql, mssql, oracle, sqlite'),
  notes: z.string().optional().describe('Any observations about the probe result'),
  set_baseline: z.boolean().optional().describe('Set this response time as the baseline for time-based detection'),
});

function createOracleProbeHandler() {
  return async function oracleProbe(args: z.infer<typeof OracleProbeSchema>): Promise<ToolResult> {
    try {
      const state = getOrCreateState(args.session_id);
      state.probeCount++;

      // Update counters
      switch (args.result) {
        case 'true': state.trueCount++; break;
        case 'false': state.falseCount++; break;
        case 'error': state.errorCount++; break;
        case 'timeout': state.trueCount++; break; // Timeout = true for time-based
      }

      // Track response times for time-based oracle
      if (args.response_time_ms !== undefined) {
        state.avgResponseMs = (state.avgResponseMs * (state.probeCount - 1) + args.response_time_ms) / state.probeCount;

        if (args.set_baseline) {
          state.baselineMs = args.response_time_ms;
        }
      }

      // Record extracted character
      if (args.extracted_char) {
        state.extractedData += args.extracted_char;
      }

      // Record DB type
      if (args.db_type) {
        state.dbType = args.db_type;
      }

      // Calculate extraction speed
      const elapsedSec = (Date.now() - state.startedAt) / 1000;
      const charsPerMinute = state.extractedData.length > 0
        ? (state.extractedData.length / elapsedSec) * 60
        : 0;

      // Time-based analysis
      let timeAnalysis = '';
      if (args.probe_type === 'time' && state.baselineMs !== null && args.response_time_ms !== undefined) {
        const delta = args.response_time_ms - state.baselineMs;
        const isDelayed = delta > (state.baselineMs * 0.5); // 50% above baseline = delayed
        timeAnalysis = isDelayed
          ? `Response ${delta}ms above baseline (${state.baselineMs}ms) — likely TRUE`
          : `Response within baseline range — likely FALSE`;
      }

      const response = {
        status: 'success' as const,
        message: `Oracle probe #${state.probeCount}: ${args.result}${args.extracted_char ? ` → extracted '${args.extracted_char}'` : ''}`,
        state: {
          total_probes: state.probeCount,
          true_count: state.trueCount,
          false_count: state.falseCount,
          error_count: state.errorCount,
          extracted_so_far: state.extractedData || '(none yet)',
          chars_extracted: state.extractedData.length,
          extraction_speed: `${charsPerMinute.toFixed(1)} chars/min`,
          avg_response_ms: Math.round(state.avgResponseMs),
          baseline_ms: state.baselineMs,
          db_type: state.dbType,
          elapsed_seconds: Math.round(elapsedSec),
        },
        time_analysis: timeAnalysis || undefined,
        next_steps: generateNextSteps(state, args),
      };

      return createToolResult(response as any);
    } catch (error) {
      return createToolResult({
        status: 'error',
        message: `Oracle probe failed: ${error instanceof Error ? error.message : String(error)}`,
        errorType: 'OracleError',
        retryable: false,
      });
    }
  };
}

function generateNextSteps(state: OracleState, args: z.infer<typeof OracleProbeSchema>): string[] {
  const steps: string[] = [];

  if (state.probeCount === 1 && !state.dbType) {
    steps.push('Identify database type using version-specific probes (e.g., @@version for MySQL, version() for PostgreSQL)');
  }

  if (state.probeCount <= 3 && args.probe_type === 'time' && state.baselineMs === null) {
    steps.push('Set a baseline response time with set_baseline=true on a known-false probe');
  }

  if (state.errorCount > state.probeCount * 0.5) {
    steps.push('High error rate detected. Consider adjusting payload syntax or checking if the injection point is still valid.');
  }

  if (state.extractedData.length > 0 && state.extractedData.length % 10 === 0) {
    steps.push(`Extracted ${state.extractedData.length} chars so far: "${state.extractedData}". Use record_technique to save progress.`);
  }

  if (steps.length === 0) {
    steps.push('Continue binary search extraction. Use SUBSTRING/ASCII/comparison operators to narrow down the next character.');
  }

  return steps;
}

/**
 * Create oracle_probe MCP tool
 */
export function createOracleProbeTool() {
  return tool(
    'oracle_probe',
    'Track blind injection oracle probes. Records boolean/time/error-based probe results, tracks extracted data, measures response timing for time-based oracles, and provides extraction progress. Use this for systematic blind SQLi, blind XPath, or blind command injection data extraction.',
    OracleProbeSchema.shape,
    createOracleProbeHandler()
  );
}
