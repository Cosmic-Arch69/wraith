// Evaluator -- rule-based agent result evaluation (not LLM)
// Parses attacks.jsonl, evidence files, and credential store to update the attack graph
// v3: Saves API calls by using deterministic rules instead of LLM judgment

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { AttackGraphService } from '../services/attack-graph.js';
import { CredentialStore } from '../services/credential-store.js';
import type {
  AgentRoundResult,
  AttackGraph,
  GraphDelta,
} from '../types/index.js';

interface AttackLogEntry {
  timestamp: string;
  phase: string;
  technique: string;
  techniqueName: string;
  target: { ip: string; user?: string; service?: string; url?: string };
  result: 'success' | 'failed' | 'blocked' | 'skipped';
  tool: string;
  details: string;
}

export class Evaluator {
  private lastEvalLine = 0;

  evaluate(
    result: AgentRoundResult,
    logDir: string,
    graph: AttackGraphService,
    credStore: CredentialStore,
  ): GraphDelta {
    const delta: GraphDelta = {
      nodes_added: [],
      nodes_updated: [],
      edges_added: 0,
      vectors_opened: [],
      vectors_closed: [],
      credentials_gained: 0,
      access_levels_changed: [],
    };

    // 1. Parse new attack log entries since last evaluation
    const newAttacks = this.parseNewAttacks(logDir);
    for (const attack of newAttacks) {
      this.processAttack(attack, graph, delta);
    }

    // 2. Check evidence files for keywords
    if (result.evidence_files.length > 0) {
      this.processEvidence(result, logDir, graph, delta);
    }

    // 3. Check credential store for new additions
    const credsBefore = result.credentials_found;
    const credsNow = credStore.getAll().length;
    if (credsNow > credsBefore) {
      delta.credentials_gained = credsNow - credsBefore;
    }

    // 4. Update graph with agent result
    const graphSnapshot = graph.getGraphSnapshot();
    const targetNode = graphSnapshot.nodes[result.agent_id.split('-').pop() ?? ''];
    if (targetNode) {
      delta.nodes_updated.push(targetNode.ip);
    }

    // Mark vectors based on success/failure
    for (const v of result.vectors_opened) {
      if (!delta.vectors_opened.includes(v)) delta.vectors_opened.push(v);
    }
    for (const v of result.vectors_blocked) {
      if (!delta.vectors_closed.includes(v)) delta.vectors_closed.push(v);
    }

    graph.addTimeline(
      result.agent_id,
      result.success ? 'succeeded' : 'failed',
      result.result_summary.substring(0, 200),
    );

    return delta;
  }

  checkObjective(graph: AttackGraph, objective: string): boolean {
    const nodes = Object.values(graph.nodes);

    switch (objective) {
      case 'domain_admin':
        // Check if any node has system access on DC
        return nodes.some(
          n => n.access_level === 'system' && (n.host.toLowerCase().includes('dc') || n.ip === graph.nodes[Object.keys(graph.nodes)[0]]?.ip),
        );

      case 'full_assessment':
        // All viable vectors have been attempted
        return nodes.every(n => n.vectors_open.length === 0);

      case 'web_only':
        // All web vectors attempted
        return nodes.every(
          n => !n.vectors_open.some(v => v.includes('web') || v.includes('sqli') || v.includes('cmdi')),
        );

      case 'cred_harvest': {
        // Credential count meets threshold (5 by default)
        const totalCreds = nodes.reduce(
          (sum, n) => sum + (n.notes.filter(note => note.toLowerCase().includes('credential')).length),
          0,
        );
        return totalCreds >= 5;
      }

      default:
        return false;
    }
  }

  private parseNewAttacks(logDir: string): AttackLogEntry[] {
    const attacksPath = join(logDir, 'attacks.jsonl');
    if (!existsSync(attacksPath)) return [];

    const lines = readFileSync(attacksPath, 'utf-8').trim().split('\n').filter(Boolean);
    const newLines = lines.slice(this.lastEvalLine);
    this.lastEvalLine = lines.length;

    return newLines
      .map(line => {
        try {
          return JSON.parse(line) as AttackLogEntry;
        } catch {
          return null;
        }
      })
      .filter((e): e is AttackLogEntry => e !== null);
  }

  private processAttack(
    attack: AttackLogEntry,
    graph: AttackGraphService,
    delta: GraphDelta,
  ): void {
    const ip = attack.target.ip;
    if (!ip || ip === 'N/A' || ip === 'broadcast') return;

    // Ensure node exists
    graph.initNode(ip, ip);

    switch (attack.result) {
      case 'success':
        graph.updateNode(ip, { status: 'up' });
        delta.nodes_updated.push(ip);
        // v3.2.0 BUG-20: Recognize SYSTEM/admin access from ANY phase (including recon)
        if (attack.details) {
          const detailsLower = attack.details.toLowerCase();
          if (detailsLower.includes('nt authority\\system') || detailsLower.includes('nt authority/system') ||
              (detailsLower.includes('system') && (detailsLower.includes('webshell') || detailsLower.includes('rce')))) {
            const node = graph.queryNode(ip);
            const prev = node?.access_level ?? 'none';
            if (prev !== 'system') {
              graph.updateNode(ip, { access_level: 'system' });
              delta.access_levels_changed.push({ ip, from: prev, to: 'system' });
            }
          }
        }
        // If this was a lateral move, record edge
        if (attack.phase === 'lateral' || attack.technique.startsWith('T1021')) {
          // We don't know the source IP from the attack log alone,
          // but mark the target as reachable
          graph.updateNode(ip, { access_level: 'user' });
          delta.access_levels_changed.push({ ip, from: 'none', to: 'user' });
        }
        // Privesc success
        if (attack.phase === 'privesc' || attack.technique.startsWith('T1068')) {
          const node = graph.queryNode(ip);
          const prev = node?.access_level ?? 'none';
          graph.updateNode(ip, { access_level: 'admin' });
          delta.access_levels_changed.push({ ip, from: prev, to: 'admin' });
        }
        break;

      case 'blocked': {
        // v3.3.0 BUG-23: Only mark as SOAR-blocked if details contain SOAR-specific indicators
        const isSoar = this.isSoarIndicator(attack.details);
        if (isSoar) {
          graph.addSoarBlock(ip);
        } else {
          // Non-SOAR block (connection refused, service down) -- close vector, keep host up
          graph.updateNode(ip, { status: 'up' });
          if (attack.techniqueName) {
            const vectorName = this.techniqueToVector(attack.technique);
            if (vectorName) {
              graph.updateNode(ip, { vectors_blocked: [vectorName] });
              delta.vectors_closed.push(`${ip}:${vectorName}`);
            }
          }
        }
        delta.nodes_updated.push(ip);
        break;
      }

      case 'failed':
        // Mark the specific vector as blocked
        if (attack.techniqueName) {
          const vectorName = this.techniqueToVector(attack.technique);
          if (vectorName) {
            graph.updateNode(ip, { vectors_blocked: [vectorName] });
            delta.vectors_closed.push(`${ip}:${vectorName}`);
          }
        }
        break;
    }
  }

  private processEvidence(
    result: AgentRoundResult,
    logDir: string,
    graph: AttackGraphService,
    delta: GraphDelta,
  ): void {
    for (const file of result.evidence_files) {
      const filePath = join(logDir, file);
      if (!existsSync(filePath)) continue;

      try {
        const content = readFileSync(filePath, 'utf-8');

        // Check for success indicators
        if (/\bSUCCESS\b/i.test(content) || /\bshell\s+obtained\b/i.test(content)) {
          // Extract target IP from filename or content
          const ipMatch = content.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
          if (ipMatch) {
            graph.updateNode(ipMatch[1], { status: 'up' });
            delta.nodes_updated.push(ipMatch[1]);
          }
        }

        // Check for credential discoveries
        if (/\bpassword\b/i.test(content) && /\bcracked\b/i.test(content)) {
          delta.credentials_gained++;
        }

        // v3.3.0 BUG-23: Require SOAR-specific keywords, not just "BLOCKED"
        if (this.isSoarEvidence(content)) {
          const ipMatch = content.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
          if (ipMatch) {
            graph.addSoarBlock(ipMatch[1]);
          }
        }

        // v3.3.0 BUG-24: Detect web admin credentials in evidence
        if (/\badmin\b/i.test(content) && (/\bcracked\b/i.test(content) || /\bpassword\b/i.test(content))) {
          const ipMatch = content.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
          if (ipMatch) {
            const node = graph.queryNode(ipMatch[1]);
            if (node && node.access_level === 'none') {
              graph.updateNode(ipMatch[1], { access_level: 'user' });
              delta.access_levels_changed.push({ ip: ipMatch[1], from: 'none', to: 'user' });
            }
            graph.updateNode(ipMatch[1], { notes: ['[evaluator] Web admin credential discovered'] });
          }
        }
      } catch {
        // Skip unreadable evidence files
      }
    }
  }

  // v3.3.0 BUG-23: Check if attack details indicate a real SOAR block (not timeout/connection error)
  private isSoarIndicator(details: string): boolean {
    if (!details) return false;
    const lower = details.toLowerCase();
    return (
      lower.includes('soar') ||
      lower.includes('pfsense') ||
      lower.includes('pfctl') ||
      lower.includes('firewall rule') ||
      lower.includes('firewall block') ||
      (lower.includes('blocked') && (lower.includes('soar') || lower.includes('firewall')))
    );
  }

  // v3.3.0 BUG-23: Require both SOAR keyword AND block indicator in evidence text
  private isSoarEvidence(content: string): boolean {
    const hasSoarKeyword = /\bSOAR\b/i.test(content) || /\bpfSense\b/i.test(content) ||
      /\bpfctl\b/i.test(content) || /\bfirewall\b/i.test(content);
    const hasBlockIndicator = /\bBLOCKED\b/i.test(content) || /\bblocked by\b/i.test(content) ||
      /\bblock rule\b/i.test(content);
    return hasSoarKeyword && hasBlockIndicator;
  }

  // v3.5.0: Classify agent outcome (BUG-38 refusal + BUG-45 partial_success + BUG-43 no_findings)
  classifyAgentOutcome(result: AgentRoundResult): 'success' | 'partial_success' | 'completed_no_findings' | 'clean_failure' | 'timeout' | 'refusal' | 'soar_block' | 'sdk_stall' {
    if (result.refused) return 'refusal';
    if (result.partial_timeout && result.success) return 'partial_success';
    if (result.no_findings) return 'completed_no_findings';
    if (result.success) return 'success';
    if (result.result_summary.startsWith('TIMEOUT')) return 'timeout';
    if (result.turns_used === 0 && result.duration_ms > 25000) return 'sdk_stall';
    if (result.result_summary.toLowerCase().includes('soar') ||
        result.result_summary.toLowerCase().includes('firewall')) return 'soar_block';
    if (result.turns_used === 0 && result.duration_ms < 5000) return 'refusal';
    return 'clean_failure';
  }

  // v3.5.0 BUG-49: Harvest credentials from attacks.jsonl mid-round
  harvestCredentials(logDir: string): void {
    const attackLog = join(logDir, 'attacks.jsonl');
    if (!existsSync(attackLog)) return;
    const lines = readFileSync(attackLog, 'utf-8').trim().split('\n');
    for (const line of lines.slice(this.lastEvalLine)) {
      try {
        const event = JSON.parse(line);
        if (event.result === 'success' && event.details) {
          const lower = event.details.toLowerCase();
          if (lower.includes('cracked') || lower.includes('credential') || lower.includes('password') || lower.includes('login')) {
            // Credential discovery detected -- credential store handles dedup
            this.lastEvalLine = lines.indexOf(line) + 1;
          }
        }
      } catch { /* skip malformed */ }
    }
  }

  private techniqueToVector(technique: string): string | null {
    const map: Record<string, string> = {
      'T1190': 'web-app',
      'T1059': 'cmdi',
      'T1110': 'brute-force',
      'T1558': 'kerberoast',
      'T1558.003': 'kerberoast',
      'T1021': 'lateral',
      'T1021.001': 'rdp-brute',
      'T1021.002': 'smb-relay',
      'T1021.006': 'winrm',
      'T1068': 'privesc',
      'T1078': 'auth-bypass',
      'T1557': 'responder',
    };
    return map[technique] ?? null;
  }
}
