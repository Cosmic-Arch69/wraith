// ReACT Report Generator -- evidence-first pentesting report
// v3.3.0: Evidence pre-collected and injected into prompt (no runtime tool calls)
// Adapted from MiroFish report_agent.py pattern + PentestAgent CSV-first pattern

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { runAgent } from '../ai/claude-executor.js';
import { loadPrompt } from '../services/prompt-manager.js';
import { ATTACK_TECHNIQUE_LABELS } from '../types/index.js';
import type {
  AttackGraph,
  ReportOutline,
  RoundResult,
  WraithV3Config,
} from '../types/index.js';

// v3.3.0: Pre-collected evidence structure (replaces runtime tool calls)
export interface PreCollectedEvidence {
  graphSummary: string;
  nodeDetails: Record<string, string>;
  allEvidence: string;
  detectionCoverage: string;
  attackToolList: string[];
  roundSummaries: string[];
}

export class ReportGenerator {
  private graph!: AttackGraph;
  private rounds!: RoundResult[];
  private preCollected!: PreCollectedEvidence;

  // v3.3.0: Pre-collect all evidence before report generation (BUG-30/31 fix)
  static preCollectEvidence(
    graph: AttackGraph,
    rounds: RoundResult[],
    logDir: string,
  ): PreCollectedEvidence {
    const allNodes = Object.values(graph.nodes);
    // v3.6.0 BUG-NEW-12: Filter out subnet entries from host count
    const nodes = allNodes.filter(n => !n.ip.includes('/'));

    // Graph summary
    const graphLines = [
      `Hosts: ${nodes.length}`,
      `Active: ${nodes.filter(n => n.status === 'up').length}`,
      `Blocked: ${nodes.filter(n => n.status === 'blocked').length}`,
      `Pivots: ${graph.pivot_points.length}`,
      `SOAR blocks: ${graph.soar_blocked_ips.join(', ') || 'none'}`,
    ];
    for (const node of nodes) {
      graphLines.push(`\n${node.host} (${node.ip}): status=${node.status}, access=${node.access_level}, services=${node.services.join(',')}, open_vectors=${node.vectors_open.join(',')}, blocked_vectors=${node.vectors_blocked.join(',')}`);
    }

    // Node details
    const nodeDetails: Record<string, string> = {};
    for (const node of nodes) {
      nodeDetails[node.ip] = JSON.stringify(node, null, 2);
    }

    // All evidence files -- BUG-47: filter out refusal content
    const REFUSAL_INDICATORS = ["I'm not going to", "I need to decline", "prompt injection", "I appreciate the detailed context, but", "I appreciate the detailed scenario, but"];
    const evidenceParts: string[] = [];
    if (existsSync(logDir)) {
      for (const f of readdirSync(logDir)) {
        if (f.endsWith('_evidence.md') ||
            (f.startsWith('agent-') && f.endsWith('-output.md')) ||
            f === 'nuclei_evidence.md') {
          try {
            const content = readFileSync(join(logDir, f), 'utf-8');
            // BUG-47: Skip evidence files that contain refusal text
            if (REFUSAL_INDICATORS.some(p => content.includes(p))) {
              evidenceParts.push(`### ${f}\n[Agent declined -- output excluded from report]`);
              continue;
            }
            evidenceParts.push(`### ${f}\n${content.substring(0, 3000)}`);
          } catch { /* skip */ }
        }
      }
    }

    // Credentials
    const credsPath = join(logDir, 'credentials.json');
    if (existsSync(credsPath)) {
      try {
        const creds = readFileSync(credsPath, 'utf-8');
        evidenceParts.push(`### credentials.json\n${creds.substring(0, 2000)}`);
      } catch { /* skip */ }
    }

    // Detection coverage from attacks.jsonl
    const attacksPath = join(logDir, 'attacks.jsonl');
    const toolSet = new Set<string>();
    let detectionSummary = 'No attacks.jsonl found.';
    if (existsSync(attacksPath)) {
      const lines = readFileSync(attacksPath, 'utf-8').trim().split('\n').filter(Boolean);
      const attacks = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      for (const a of attacks) {
        if (a.tool) toolSet.add(a.tool);
      }
      const byTechnique: Record<string, { total: number; success: number; blocked: number; failed: number }> = {};
      for (const a of attacks) {
        const t = a.technique ?? 'unknown';
        if (!byTechnique[t]) byTechnique[t] = { total: 0, success: 0, blocked: 0, failed: 0 };
        byTechnique[t].total++;
        if (a.result === 'success') byTechnique[t].success++;
        if (a.result === 'blocked') byTechnique[t].blocked++;
        if (a.result === 'failed') byTechnique[t].failed++;
      }
      // v3.6.0 BUG-NEW-13: Use canonical ATT&CK technique labels
      detectionSummary = `Total attacks: ${attacks.length}\n` +
        Object.entries(byTechnique)
          .map(([t, s]) => {
            const label = ATTACK_TECHNIQUE_LABELS[t] ?? t;
            return `${t} (${label}): ${s.total} attempts, ${s.success} success, ${s.blocked} blocked, ${s.failed} failed`;
          })
          .join('\n');
    }

    // Round summaries -- BUG-47: sanitize refusal text from agent summaries
    const roundSummaries = rounds.map(r => {
      const agents = r.agent_results.map(a => {
        let summary = a.result_summary.substring(0, 150);
        if (a.refused || REFUSAL_INDICATORS.some(p => summary.includes(p))) {
          summary = '[Agent declined -- output excluded from report]';
        }
        return `  - ${a.agent_id}: ${a.success ? 'SUCCESS' : a.partial_timeout ? 'PARTIAL' : 'FAILED'} (${a.turns_used} turns, ${a.duration_ms}ms) -- ${summary}`;
      }).join('\n');
      return `### Round ${r.round}\n${agents}`;
    });

    return {
      graphSummary: graphLines.join('\n'),
      nodeDetails,
      allEvidence: evidenceParts.join('\n\n'),
      detectionCoverage: detectionSummary,
      attackToolList: Array.from(toolSet),
      roundSummaries,
    };
  }

  async generateReport(
    graph: AttackGraph,
    rounds: RoundResult[],
    logDir: string,
    config: WraithV3Config,
    evidence?: PreCollectedEvidence,
  ): Promise<string> {
    this.graph = graph;
    this.rounds = rounds;
    this.preCollected = evidence ?? ReportGenerator.preCollectEvidence(graph, rounds, logDir);

    // 1. Generate outline
    const outline = this.planOutline(config);
    console.log(`[report] Outline: ${outline.sections.length} sections`);

    // 2. Generate each section with pre-injected evidence
    const sections: string[] = [];
    sections.push(`# ${outline.title}\n\n${outline.executive_summary}\n`);

    for (const section of outline.sections) {
      console.log(`[report] Writing section: ${section.title}`);
      const content = await this.generateSection(section, outline, sections, config);
      sections.push(content);
    }

    return sections.join('\n\n---\n\n');
  }

  private planOutline(config: WraithV3Config): ReportOutline {
    const nodes = Object.values(this.graph.nodes);
    const totalSuccesses = this.rounds.reduce(
      (s, r) => s + r.agent_results.filter(a => a.success).length, 0,
    );

    return {
      title: `Penetration Test Report -- ${config.target.domain}`,
      executive_summary: `This report documents the findings from an automated penetration test conducted against ${config.target.domain}. The assessment covered ${nodes.length} hosts across ${this.rounds.length} attack rounds, with ${totalSuccesses} successful attack vectors identified.`,
      sections: [
        { title: 'Methodology', description: 'Overview of the automated assessment approach, tools used, and attack phases.' },
        { title: 'Findings', description: 'Detailed security findings organized by severity with evidence and remediation.' },
        { title: 'Attack Narrative', description: 'Timeline-based walkthrough of the engagement from recon to final objective.' },
        { title: 'Detection Analysis', description: 'Analysis of what the SOAR/SIEM detected vs. what it missed.' },
        { title: 'Recommendations', description: 'Prioritized remediation roadmap with quick wins and strategic improvements.' },
      ],
    };
  }

  // v3.3.0: Single-pass evidence-injected section generation (replaces ReACT loop)
  private async generateSection(
    section: { title: string; description: string },
    outline: ReportOutline,
    previousSections: string[],
    config: WraithV3Config,
  ): Promise<string> {
    // Build evidence context based on section type
    const evidenceContext = this.buildSectionEvidence(section.title);

    // Build prompt
    const prompt = await loadPrompt('report-react', {
      domain: config.target.domain,
      dc: config.target.dc,
      engagement_type: config.engagement?.type ?? 'internal',
      date: new Date().toISOString().split('T')[0],
      rounds_completed: String(this.rounds.length),
      report_outline: outline.sections.map(s => `- **${s.title}**: ${s.description}`).join('\n'),
      section_title: section.title,
      section_description: section.description,
      previous_sections: previousSections.length > 0
        ? previousSections.join('\n\n').substring(0, 5000)
        : '(None yet -- this is the first section)',
    });

    // Inject evidence directly into the prompt
    const fullPrompt = [
      `## Pre-Collected Evidence\n\n${evidenceContext}`,
      '---',
      prompt,
      '',
      'IMPORTANT: All evidence has been pre-collected above. Do NOT attempt tool calls. Write your section directly from the evidence provided. If evidence is insufficient for a claim, state that explicitly.',
    ].join('\n\n');

    const result = await runAgent(fullPrompt, `report-${section.title}`, 'small', {}, 15);

    if (!result.success || !result.result) {
      console.warn(`[report] Section "${section.title}" generation failed -- using placeholder`);
      return `## ${section.title}\n\n*Section could not be generated due to an error.*`;
    }

    // Extract content (handle "Final Answer:" prefix if present)
    let text = result.result;
    const finalMatch = text.match(/\*\*Final Answer:\*\*([\s\S]*)/i)
      ?? text.match(/Final Answer:([\s\S]*)/i);
    if (finalMatch) text = finalMatch[1].trim();

    // Clean duplicate numbered headers
    const cleaned = text.replace(/^#{1,3}\s*\d+\.?\s*/gm, '');
    return `## ${section.title}\n\n${cleaned}`;
  }

  // v3.3.0: Assemble section-specific evidence from pre-collected data
  private buildSectionEvidence(sectionTitle: string): string {
    const parts: string[] = [];
    const lower = sectionTitle.toLowerCase();

    // All sections get graph summary
    parts.push(`### Attack Graph Summary\n${this.preCollected.graphSummary}`);

    if (lower.includes('methodology')) {
      // BUG-31 fix: actual tool list prevents hallucination
      parts.push(`### Tools Actually Used (from attacks.jsonl)\n${this.preCollected.attackToolList.join(', ') || 'No tools recorded in attack log'}`);
      parts.push(`### Round Summaries\n${this.preCollected.roundSummaries.join('\n\n')}`);
      parts.push(`### Detection Coverage\n${this.preCollected.detectionCoverage}`);
    }

    if (lower.includes('finding')) {
      parts.push(`### Evidence Files\n${this.preCollected.allEvidence.substring(0, 10000)}`);
      parts.push(`### Detection Coverage\n${this.preCollected.detectionCoverage}`);
    }

    if (lower.includes('narrative') || lower.includes('attack')) {
      parts.push(`### Round Summaries\n${this.preCollected.roundSummaries.join('\n\n')}`);
      parts.push(`### Evidence Files\n${this.preCollected.allEvidence.substring(0, 8000)}`);
    }

    if (lower.includes('detection')) {
      parts.push(`### Detection Coverage\n${this.preCollected.detectionCoverage}`);
    }

    if (lower.includes('recommend')) {
      parts.push(`### Detection Coverage\n${this.preCollected.detectionCoverage}`);
      parts.push(`### Evidence Files\n${this.preCollected.allEvidence.substring(0, 5000)}`);
    }

    return parts.join('\n\n');
  }
}
