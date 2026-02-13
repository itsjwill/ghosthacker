// Copyright (C) 2026 Ghost Hacker Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Persistent Intelligence Database
 *
 * SQLite-backed cross-scan intelligence that persists across all Ghost Hacker
 * engagements. Every successful technique, payload bypass, WAF evasion, and
 * vulnerability pattern is stored and queryable by future scans.
 *
 * Ghost Hacker gets smarter with every engagement.
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { GHOSTHACKER_ROOT } from '../audit/utils.js';

const INTEL_DB_PATH = path.join(GHOSTHACKER_ROOT, 'intel.db');

export interface Technique {
  id?: number;
  scan_id: string;
  target_hostname: string;
  tech_stack: string;         // JSON: {language, framework, database, waf}
  vuln_type: string;          // injection, xss, auth, ssrf, authz, secrets, variants
  technique_name: string;     // e.g., "union-based-sqli", "dom-xss-via-postmessage"
  payload: string;            // The actual payload that worked
  success: boolean;
  bypassed_defenses: string;  // JSON array of defense names bypassed
  blocked_by: string;         // JSON array of what blocked it (if failed)
  response_pattern: string;   // How the app responded (for fingerprinting)
  severity: string;           // critical, high, medium, low
  notes: string;
  created_at?: string;
}

export interface AppSignature {
  id?: number;
  hostname: string;
  tech_stack: string;         // JSON: {language, framework, database, waf, version}
  fingerprint: string;        // Unique hash of tech stack combination
  first_seen?: string;
  last_seen?: string;
  scan_count?: number;
}

export interface VulnPattern {
  id?: number;
  pattern_name: string;       // e.g., "express-nosql-injection", "django-ssti"
  description: string;
  tech_stack_match: string;   // JSON: partial tech stack to match against
  indicators: string;         // JSON: code patterns or response patterns that indicate this vuln
  recommended_payloads: string; // JSON array of payloads to try
  success_rate: number;       // 0.0 - 1.0
  sample_size: number;
  created_at?: string;
  updated_at?: string;
}

export interface IntelQuery {
  vuln_type?: string;
  tech_stack?: Partial<TechStackInfo>;
  hostname?: string;
  success_only?: boolean;
  limit?: number;
}

export interface TechStackInfo {
  language: string;
  framework: string;
  database: string;
  waf: string | null;
  version?: string;
}

export interface TechniqueStats {
  technique_name: string;
  total_attempts: number;
  successes: number;
  success_rate: number;
  common_bypasses: string[];
  common_blockers: string[];
}

export class PersistentIntelDB {
  private db: Database.Database;

  constructor(dbPath: string = INTEL_DB_PATH) {
    // Ensure directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('busy_timeout = 5000');
    this.initialize();
  }

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS techniques (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        target_hostname TEXT NOT NULL,
        tech_stack TEXT DEFAULT '{}',
        vuln_type TEXT NOT NULL,
        technique_name TEXT NOT NULL,
        payload TEXT NOT NULL,
        success INTEGER NOT NULL DEFAULT 0,
        bypassed_defenses TEXT DEFAULT '[]',
        blocked_by TEXT DEFAULT '[]',
        response_pattern TEXT DEFAULT '',
        severity TEXT DEFAULT 'medium',
        notes TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS app_signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT NOT NULL UNIQUE,
        tech_stack TEXT DEFAULT '{}',
        fingerprint TEXT NOT NULL,
        first_seen TEXT DEFAULT (datetime('now')),
        last_seen TEXT DEFAULT (datetime('now')),
        scan_count INTEGER DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL UNIQUE,
        target_url TEXT NOT NULL,
        hostname TEXT NOT NULL,
        tech_stack TEXT DEFAULT '{}',
        vulns_found INTEGER DEFAULT 0,
        vulns_exploited INTEGER DEFAULT 0,
        started_at TEXT DEFAULT (datetime('now')),
        completed_at TEXT
      );

      CREATE TABLE IF NOT EXISTS vulnerability_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_name TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '',
        tech_stack_match TEXT DEFAULT '{}',
        indicators TEXT DEFAULT '[]',
        recommended_payloads TEXT DEFAULT '[]',
        success_rate REAL DEFAULT 0.0,
        sample_size INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_techniques_vuln_type ON techniques(vuln_type);
      CREATE INDEX IF NOT EXISTS idx_techniques_hostname ON techniques(target_hostname);
      CREATE INDEX IF NOT EXISTS idx_techniques_success ON techniques(success);
      CREATE INDEX IF NOT EXISTS idx_techniques_technique ON techniques(technique_name);
      CREATE INDEX IF NOT EXISTS idx_scan_history_hostname ON scan_history(hostname);
    `);
  }

  /**
   * Record a successful or failed technique attempt
   */
  recordTechnique(technique: Technique): number {
    const stmt = this.db.prepare(`
      INSERT INTO techniques (
        scan_id, target_hostname, tech_stack, vuln_type, technique_name,
        payload, success, bypassed_defenses, blocked_by, response_pattern,
        severity, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      technique.scan_id,
      technique.target_hostname,
      technique.tech_stack,
      technique.vuln_type,
      technique.technique_name,
      technique.payload,
      technique.success ? 1 : 0,
      technique.bypassed_defenses,
      technique.blocked_by,
      technique.response_pattern,
      technique.severity,
      technique.notes
    );

    return result.lastInsertRowid as number;
  }

  /**
   * Query intelligence database for relevant techniques
   */
  queryIntelligence(query: IntelQuery): Technique[] {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (query.vuln_type) {
      conditions.push('vuln_type = ?');
      params.push(query.vuln_type);
    }

    if (query.hostname) {
      conditions.push('target_hostname = ?');
      params.push(query.hostname);
    }

    if (query.success_only) {
      conditions.push('success = 1');
    }

    if (query.tech_stack) {
      // Match on partial tech stack (any matching field)
      const stack = query.tech_stack;
      if (stack.framework) {
        conditions.push("json_extract(tech_stack, '$.framework') = ?");
        params.push(stack.framework);
      }
      if (stack.language) {
        conditions.push("json_extract(tech_stack, '$.language') = ?");
        params.push(stack.language);
      }
      if (stack.database) {
        conditions.push("json_extract(tech_stack, '$.database') = ?");
        params.push(stack.database);
      }
      if (stack.waf) {
        conditions.push("json_extract(tech_stack, '$.waf') = ?");
        params.push(stack.waf);
      }
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = query.limit || 50;

    const stmt = this.db.prepare(`
      SELECT * FROM techniques ${where}
      ORDER BY success DESC, created_at DESC
      LIMIT ?
    `);

    return stmt.all(...params, limit) as Technique[];
  }

  /**
   * Find targets with similar tech stacks
   */
  findSimilarTargets(techStack: Partial<TechStackInfo>): AppSignature[] {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (techStack.framework) {
      conditions.push("json_extract(tech_stack, '$.framework') = ?");
      params.push(techStack.framework);
    }
    if (techStack.language) {
      conditions.push("json_extract(tech_stack, '$.language') = ?");
      params.push(techStack.language);
    }
    if (techStack.database) {
      conditions.push("json_extract(tech_stack, '$.database') = ?");
      params.push(techStack.database);
    }

    if (conditions.length === 0) return [];

    const where = `WHERE ${conditions.join(' OR ')}`;
    const stmt = this.db.prepare(`SELECT * FROM app_signatures ${where} ORDER BY scan_count DESC LIMIT 20`);
    return stmt.all(...params) as AppSignature[];
  }

  /**
   * Get success rate for a technique against a specific tech stack
   */
  getSuccessRate(techniqueName: string, techStack?: Partial<TechStackInfo>): TechniqueStats {
    const conditions: string[] = ['technique_name = ?'];
    const params: unknown[] = [techniqueName];

    if (techStack?.framework) {
      conditions.push("json_extract(tech_stack, '$.framework') = ?");
      params.push(techStack.framework);
    }

    const where = conditions.join(' AND ');

    const row = this.db.prepare(`
      SELECT
        technique_name,
        COUNT(*) as total_attempts,
        SUM(success) as successes,
        CAST(SUM(success) AS REAL) / COUNT(*) as success_rate
      FROM techniques
      WHERE ${where}
      GROUP BY technique_name
    `).get(...params) as { technique_name: string; total_attempts: number; successes: number; success_rate: number } | undefined;

    if (!row) {
      return {
        technique_name: techniqueName,
        total_attempts: 0,
        successes: 0,
        success_rate: 0,
        common_bypasses: [],
        common_blockers: [],
      };
    }

    // Get common bypasses and blockers
    const bypasses = this.db.prepare(`
      SELECT bypassed_defenses FROM techniques
      WHERE technique_name = ? AND success = 1 AND bypassed_defenses != '[]'
      ORDER BY created_at DESC LIMIT 10
    `).all(techniqueName) as { bypassed_defenses: string }[];

    const blockers = this.db.prepare(`
      SELECT blocked_by FROM techniques
      WHERE technique_name = ? AND success = 0 AND blocked_by != '[]'
      ORDER BY created_at DESC LIMIT 10
    `).all(techniqueName) as { blocked_by: string }[];

    const commonBypasses = this.flattenJsonArrays(bypasses.map(b => b.bypassed_defenses));
    const commonBlockers = this.flattenJsonArrays(blockers.map(b => b.blocked_by));

    return {
      technique_name: row.technique_name,
      total_attempts: row.total_attempts,
      successes: row.successes,
      success_rate: row.success_rate,
      common_bypasses: commonBypasses,
      common_blockers: commonBlockers,
    };
  }

  /**
   * Register or update an app signature
   */
  registerTarget(hostname: string, techStack: TechStackInfo): void {
    const fingerprint = this.computeFingerprint(techStack);
    const techStackJson = JSON.stringify(techStack);

    const existing = this.db.prepare('SELECT id FROM app_signatures WHERE hostname = ?').get(hostname);

    if (existing) {
      this.db.prepare(`
        UPDATE app_signatures
        SET tech_stack = ?, fingerprint = ?, last_seen = datetime('now'), scan_count = scan_count + 1
        WHERE hostname = ?
      `).run(techStackJson, fingerprint, hostname);
    } else {
      this.db.prepare(`
        INSERT INTO app_signatures (hostname, tech_stack, fingerprint)
        VALUES (?, ?, ?)
      `).run(hostname, techStackJson, fingerprint);
    }
  }

  /**
   * Record scan start
   */
  startScan(scanId: string, targetUrl: string, hostname: string, techStack?: TechStackInfo): void {
    this.db.prepare(`
      INSERT OR IGNORE INTO scan_history (scan_id, target_url, hostname, tech_stack)
      VALUES (?, ?, ?, ?)
    `).run(scanId, targetUrl, hostname, techStack ? JSON.stringify(techStack) : '{}');
  }

  /**
   * Record scan completion
   */
  completeScan(scanId: string, vulnsFound: number, vulnsExploited: number): void {
    this.db.prepare(`
      UPDATE scan_history
      SET vulns_found = ?, vulns_exploited = ?, completed_at = datetime('now')
      WHERE scan_id = ?
    `).run(vulnsFound, vulnsExploited, scanId);
  }

  /**
   * Get recommended payloads for a vulnerability type and tech stack
   */
  getRecommendedPayloads(vulnType: string, techStack?: Partial<TechStackInfo>): string[] {
    const techniques = this.queryIntelligence({
      vuln_type: vulnType,
      ...(techStack !== undefined && { tech_stack: techStack }),
      success_only: true,
      limit: 20,
    });

    // Return unique payloads ordered by recency
    const seen = new Set<string>();
    const payloads: string[] = [];
    for (const t of techniques) {
      if (!seen.has(t.payload)) {
        seen.add(t.payload);
        payloads.push(t.payload);
      }
    }
    return payloads;
  }

  /**
   * Get summary stats for the intelligence database
   */
  getStats(): {
    totalTechniques: number;
    successfulTechniques: number;
    totalScans: number;
    uniqueTargets: number;
    topTechniques: { name: string; count: number; rate: number }[];
  } {
    const total = (this.db.prepare('SELECT COUNT(*) as count FROM techniques').get() as { count: number }).count;
    const successful = (this.db.prepare('SELECT COUNT(*) as count FROM techniques WHERE success = 1').get() as { count: number }).count;
    const scans = (this.db.prepare('SELECT COUNT(*) as count FROM scan_history').get() as { count: number }).count;
    const targets = (this.db.prepare('SELECT COUNT(DISTINCT hostname) as count FROM app_signatures').get() as { count: number }).count;

    const topTechniques = this.db.prepare(`
      SELECT technique_name as name, COUNT(*) as count,
             CAST(SUM(success) AS REAL) / COUNT(*) as rate
      FROM techniques
      GROUP BY technique_name
      ORDER BY count DESC
      LIMIT 10
    `).all() as { name: string; count: number; rate: number }[];

    return {
      totalTechniques: total,
      successfulTechniques: successful,
      totalScans: scans,
      uniqueTargets: targets,
      topTechniques,
    };
  }

  close(): void {
    this.db.close();
  }

  private computeFingerprint(techStack: TechStackInfo): string {
    const key = `${techStack.language}:${techStack.framework}:${techStack.database}:${techStack.waf || 'none'}`;
    // Simple hash
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
      const char = key.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return Math.abs(hash).toString(36);
  }

  private flattenJsonArrays(jsonStrings: string[]): string[] {
    const counts = new Map<string, number>();
    for (const jsonStr of jsonStrings) {
      try {
        const arr = JSON.parse(jsonStr) as string[];
        for (const item of arr) {
          counts.set(item, (counts.get(item) || 0) + 1);
        }
      } catch {
        // Skip invalid JSON
      }
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([item]) => item);
  }
}

// Singleton for use across a scan session
let _instance: PersistentIntelDB | null = null;

export function getIntelDB(dbPath?: string): PersistentIntelDB {
  if (!_instance) {
    _instance = new PersistentIntelDB(dbPath);
  }
  return _instance;
}

export function closeIntelDB(): void {
  if (_instance) {
    _instance.close();
    _instance = null;
  }
}
