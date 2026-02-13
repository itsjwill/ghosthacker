// Copyright (C) 2026 Ghost Hacker Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Intelligence MCP Tools
 *
 * Provides agents with access to the persistent cross-scan intelligence database.
 * - record_technique: Store successful (or failed) techniques for future scans
 * - query_intelligence: Query what worked before on similar targets/tech stacks
 */

import { tool } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';
import { createToolResult, type ToolResult } from '../types/tool-responses.js';
import { getIntelDB } from '../../src/intelligence/persistent-intel.js';

/**
 * record_technique - Store a technique attempt in the intelligence database
 */
const RecordTechniqueSchema = z.object({
  scan_id: z.string().describe('Current scan/workflow ID'),
  target_hostname: z.string().describe('Target hostname'),
  tech_stack: z.string().optional().describe('JSON string of tech stack: {language, framework, database, waf}'),
  vuln_type: z.string().describe('Vulnerability type: injection, xss, auth, ssrf, authz, secrets, variants'),
  technique_name: z.string().describe('Name of the technique: e.g., "union-based-sqli", "reflected-xss-via-search"'),
  payload: z.string().describe('The actual payload used'),
  success: z.boolean().describe('Whether the technique succeeded'),
  bypassed_defenses: z.string().optional().describe('JSON array of defenses bypassed: e.g., ["WAF", "input-validation"]'),
  blocked_by: z.string().optional().describe('JSON array of what blocked it: e.g., ["CSP", "parameterized-queries"]'),
  response_pattern: z.string().optional().describe('How the application responded (for fingerprinting)'),
  severity: z.string().optional().describe('Severity: critical, high, medium, low'),
  notes: z.string().optional().describe('Additional notes about the technique'),
});

function createRecordTechniqueHandler() {
  return async function recordTechnique(args: z.infer<typeof RecordTechniqueSchema>): Promise<ToolResult> {
    try {
      const db = getIntelDB();
      const id = db.recordTechnique({
        scan_id: args.scan_id,
        target_hostname: args.target_hostname,
        tech_stack: args.tech_stack || '{}',
        vuln_type: args.vuln_type,
        technique_name: args.technique_name,
        payload: args.payload,
        success: args.success,
        bypassed_defenses: args.bypassed_defenses || '[]',
        blocked_by: args.blocked_by || '[]',
        response_pattern: args.response_pattern || '',
        severity: args.severity || 'medium',
        notes: args.notes || '',
      });

      return createToolResult({
        status: 'success',
        message: `Technique recorded (ID: ${id}). ${args.success ? 'SUCCESS' : 'FAILED'}: ${args.technique_name} against ${args.target_hostname}`,
      });
    } catch (error) {
      return createToolResult({
        status: 'error',
        message: `Failed to record technique: ${error instanceof Error ? error.message : String(error)}`,
        errorType: 'IntelligenceError',
        retryable: false,
      });
    }
  };
}

/**
 * query_intelligence - Query the intelligence database for relevant techniques
 */
const QueryIntelligenceSchema = z.object({
  vuln_type: z.string().optional().describe('Filter by vulnerability type: injection, xss, auth, ssrf, authz'),
  hostname: z.string().optional().describe('Filter by target hostname'),
  tech_stack_framework: z.string().optional().describe('Filter by framework: express, django, spring, rails, etc.'),
  tech_stack_language: z.string().optional().describe('Filter by language: javascript, python, java, php, etc.'),
  tech_stack_database: z.string().optional().describe('Filter by database: mysql, postgresql, mongodb, etc.'),
  tech_stack_waf: z.string().optional().describe('Filter by WAF: cloudflare, modsecurity, aws-waf, etc.'),
  success_only: z.boolean().optional().describe('Only return successful techniques (default: false)'),
  limit: z.number().optional().describe('Max results to return (default: 20)'),
});

function createQueryIntelligenceHandler() {
  return async function queryIntelligence(args: z.infer<typeof QueryIntelligenceSchema>): Promise<ToolResult> {
    try {
      const db = getIntelDB();

      const techStack: Record<string, string> = {};
      if (args.tech_stack_framework) techStack.framework = args.tech_stack_framework;
      if (args.tech_stack_language) techStack.language = args.tech_stack_language;
      if (args.tech_stack_database) techStack.database = args.tech_stack_database;
      if (args.tech_stack_waf) techStack.waf = args.tech_stack_waf;

      const results = db.queryIntelligence({
        vuln_type: args.vuln_type,
        hostname: args.hostname,
        tech_stack: Object.keys(techStack).length > 0 ? techStack : undefined,
        success_only: args.success_only,
        limit: args.limit || 20,
      });

      const stats = db.getStats();

      const summary = {
        status: 'success' as const,
        message: `Found ${results.length} technique(s) in intelligence database (${stats.totalTechniques} total stored, ${stats.totalScans} past scans)`,
        results: results.map(r => ({
          technique: r.technique_name,
          vuln_type: r.vuln_type,
          payload: r.payload,
          success: r.success,
          target: r.target_hostname,
          severity: r.severity,
          bypassed: r.bypassed_defenses,
          blocked_by: r.blocked_by,
          notes: r.notes,
        })),
        database_stats: {
          total_techniques: stats.totalTechniques,
          successful_techniques: stats.successfulTechniques,
          total_scans: stats.totalScans,
          unique_targets: stats.uniqueTargets,
        },
      };

      return createToolResult(summary);
    } catch (error) {
      return createToolResult({
        status: 'error',
        message: `Failed to query intelligence: ${error instanceof Error ? error.message : String(error)}`,
        errorType: 'IntelligenceError',
        retryable: false,
      });
    }
  };
}

/**
 * Create record_technique MCP tool
 */
export function createRecordTechniqueTool() {
  return tool(
    'record_technique',
    'Record a technique attempt (successful or failed) in the cross-scan intelligence database. Call this whenever you try a payload, bypass, or exploitation technique so future scans can learn from it.',
    RecordTechniqueSchema.shape,
    createRecordTechniqueHandler()
  );
}

/**
 * Create query_intelligence MCP tool
 */
export function createQueryIntelligenceTool() {
  return tool(
    'query_intelligence',
    'Query the cross-scan intelligence database for techniques that worked (or failed) on similar targets, tech stacks, or vulnerability types. Use this BEFORE attempting exploitation to see what worked before.',
    QueryIntelligenceSchema.shape,
    createQueryIntelligenceHandler()
  );
}
