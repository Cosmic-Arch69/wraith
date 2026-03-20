// ReACT Report Generator -- tool-grounded pentesting report
// Adapted from MiroFish report_agent.py pattern
// v3: In-process tools (not MCP), iterative section generation

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { runAgent } from '../ai/claude-executor.js';
import { loadPrompt } from '../services/prompt-manager.js';
import type {
  AttackGraph,
  ReportOutline,
  RoundResult,
  WraithV3Config,
} from '../types/index.js';

// In-process report tools (no MCP server needed)
interface ToolCall {
  tool: string;
  args: Record<string, string>;
}

export class ReportGenerator {
  private graph!: AttackGraph;
  private rounds!: RoundResult[];
  private logDir!: string;

  async generateReport(
    graph: AttackGraph,
    rounds: RoundResult[],
    logDir: string,
    config: WraithV3Config,
  ): Promise<string> {
    this.graph = graph;
    this.rounds = rounds;
    this.logDir = logDir;

    const reportConfig = config.report ?? {
      react_max_iterations: 5,
      react_min_tool_calls: 3,
    };

    // 1. Generate outline
    const outline = await this.planOutline(graph, config);
    console.log(`[report] Outline: ${outline.sections.length} sections`);

    // 2. Generate each section
    const sections: string[] = [];
    sections.push(`# ${outline.title}\n\n${outline.executive_summary}\n`);

    for (const section of outline.sections) {
      console.log(`[report] Writing section: ${section.title}`);
      const content = await this.generateSection(
        section,
        outline,
        sections,
        config,
        reportConfig,
      );
      sections.push(content);
    }

    return sections.join('\n\n---\n\n');
  }

  private async planOutline(
    graph: AttackGraph,
    config: WraithV3Config,
  ): Promise<ReportOutline> {
    const nodes = Object.values(graph.nodes);
    const totalSuccesses = this.rounds.reduce(
      (s, r) => s + r.agent_results.filter(a => a.success).length, 0,
    );

    // Default outline -- deterministic, no LLM call needed
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

  private async generateSection(
    section: { title: string; description: string },
    outline: ReportOutline,
    previousSections: string[],
    config: WraithV3Config,
    reportConfig: { react_max_iterations: number; react_min_tool_calls: number },
  ): Promise<string> {
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
      min_tool_calls: String(reportConfig.react_min_tool_calls),
      max_tool_calls: String(reportConfig.react_max_iterations),
    });

    // Run ReACT loop: send prompt, parse tool calls, inject observations, repeat
    let conversation = prompt;
    let toolCallCount = 0;
    const maxIterations = reportConfig.react_max_iterations;

    for (let i = 0; i < maxIterations; i++) {
      const result = await runAgent(conversation, `report-${section.title}`, 'small', {}, 15);

      if (!result.success || !result.result) {
        console.warn(`[report] Section "${section.title}" generation failed -- using placeholder`);
        return `## ${section.title}\n\n*Section could not be generated due to an error.*`;
      }

      const text = result.result;

      // Check for Final Answer
      const finalAnswerMatch = text.match(/\*\*Final Answer:\*\*([\s\S]*)/i)
        ?? text.match(/Final Answer:([\s\S]*)/i);

      // Parse tool calls
      const toolCalls = this.parseToolCalls(text);

      if (toolCalls.length > 0 && !finalAnswerMatch) {
        // Process tool calls and inject observations
        const observations: string[] = [];
        for (const tc of toolCalls) {
          const obs = this.executeTool(tc);
          observations.push(`**Observation (${tc.tool}):** ${obs}`);
          toolCallCount++;
        }

        conversation = `${text}\n\n${observations.join('\n\n')}\n\nContinue your analysis. You have made ${toolCallCount} tool calls so far.`;
        continue;
      }

      if (finalAnswerMatch) {
        return `## ${section.title}\n\n${finalAnswerMatch[1].trim()}`;
      }

      // No tool calls and no final answer -- treat whole output as final
      return `## ${section.title}\n\n${text}`;
    }

    // Max iterations reached
    return `## ${section.title}\n\n*Section truncated after ${maxIterations} ReACT iterations.*`;
  }

  private parseToolCalls(text: string): ToolCall[] {
    const calls: ToolCall[] = [];

    // XML format: <tool_call>{"tool": "...", "args": {...}}</tool_call>
    const xmlMatches = text.matchAll(/<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/g);
    for (const match of xmlMatches) {
      try {
        const parsed = JSON.parse(match[1]);
        if (parsed.tool && parsed.args) {
          calls.push(parsed as ToolCall);
        }
      } catch { /* skip malformed */ }
    }

    // Bare JSON fallback: {"tool": "...", "args": {...}}
    if (calls.length === 0) {
      const jsonMatches = text.matchAll(/\{"tool"\s*:\s*"([^"]+)"\s*,\s*"args"\s*:\s*(\{[^}]+\})\}/g);
      for (const match of jsonMatches) {
        try {
          calls.push({
            tool: match[1],
            args: JSON.parse(match[2]),
          });
        } catch { /* skip */ }
      }
    }

    return calls;
  }

  private executeTool(call: ToolCall): string {
    switch (call.tool) {
      case 'graph_query':
        return this.toolGraphQuery(call.args);
      case 'evidence_search':
        return this.toolEvidenceSearch(call.args);
      case 'detection_analysis':
        return this.toolDetectionAnalysis(call.args);
      case 'recommendation_engine':
        return this.toolRecommendation(call.args);
      default:
        return `Unknown tool: ${call.tool}`;
    }
  }

  // Tool 1: Query attack graph
  private toolGraphQuery(args: Record<string, string>): string {
    const query = args.query ?? 'summary';

    switch (query) {
      case 'summary': {
        const nodes = Object.values(this.graph.nodes);
        const lines = [
          `Hosts: ${nodes.length}`,
          `Active: ${nodes.filter(n => n.status === 'up').length}`,
          `Blocked: ${nodes.filter(n => n.status === 'blocked').length}`,
          `Pivots: ${this.graph.pivot_points.length}`,
          `SOAR blocks: ${this.graph.soar_blocked_ips.join(', ') || 'none'}`,
        ];
        for (const node of nodes) {
          lines.push(`\n${node.host} (${node.ip}): status=${node.status}, access=${node.access_level}, services=${node.services.join(',')}, open_vectors=${node.vectors_open.join(',')}, blocked_vectors=${node.vectors_blocked.join(',')}`);
        }
        return lines.join('\n');
      }

      case 'node': {
        const ip = args.ip;
        const node = ip ? this.graph.nodes[ip] : undefined;
        if (!node) return `No node found for ${ip}`;
        return JSON.stringify(node, null, 2);
      }

      case 'open_vectors': {
        return Object.values(this.graph.nodes)
          .filter(n => n.vectors_open.length > 0)
          .map(n => `${n.host} (${n.ip}): ${n.vectors_open.join(', ')}`)
          .join('\n') || 'No open vectors remaining';
      }

      case 'edges': {
        return this.graph.edges
          .map(e => `${e.from} -> ${e.to} via ${e.via}`)
          .join('\n') || 'No edges recorded';
      }

      default:
        return `Unknown query type: ${query}`;
    }
  }

  // Tool 2: Search evidence files
  private toolEvidenceSearch(args: Record<string, string>): string {
    const keyword = args.keyword ?? '';
    const agentId = args.agent_id;
    const results: string[] = [];

    const searchDir = this.logDir;
    if (!existsSync(searchDir)) return 'No evidence directory found';

    const files = readdirSync(searchDir).filter(f =>
      f.endsWith('.md') || f.endsWith('.json') || f.endsWith('.txt'),
    );

    for (const file of files) {
      if (agentId && !file.includes(agentId.split('-')[0])) continue;

      try {
        const content = readFileSync(join(searchDir, file), 'utf-8');
        if (keyword && !content.toLowerCase().includes(keyword.toLowerCase())) continue;

        // Extract relevant lines
        const lines = content.split('\n');
        const matches = lines.filter(l =>
          l.toLowerCase().includes(keyword.toLowerCase()),
        );
        if (matches.length > 0) {
          results.push(`**${file}:**\n${matches.slice(0, 5).join('\n')}`);
        }
      } catch { /* skip */ }
    }

    return results.length > 0
      ? results.join('\n\n')
      : `No evidence found for keyword "${keyword}"${agentId ? ` in agent ${agentId}` : ''}`;
  }

  // Tool 3: Detection analysis
  private toolDetectionAnalysis(args: Record<string, string>): string {
    const techniqueId = args.technique_id ?? 'all';
    const attacksPath = join(this.logDir, 'attacks.jsonl');
    if (!existsSync(attacksPath)) return 'No attacks.jsonl found';

    const lines = readFileSync(attacksPath, 'utf-8').trim().split('\n').filter(Boolean);
    const attacks = lines.map(l => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);

    if (techniqueId === 'all') {
      const byTechnique: Record<string, { total: number; success: number; blocked: number }> = {};
      for (const a of attacks) {
        const t = a.technique ?? 'unknown';
        if (!byTechnique[t]) byTechnique[t] = { total: 0, success: 0, blocked: 0 };
        byTechnique[t].total++;
        if (a.result === 'success') byTechnique[t].success++;
        if (a.result === 'blocked') byTechnique[t].blocked++;
      }
      const summaryLines = Object.entries(byTechnique).map(
        ([t, stats]) => `${t}: ${stats.total} attempts, ${stats.success} success, ${stats.blocked} blocked`,
      );
      return `Detection coverage:\n${summaryLines.join('\n')}`;
    }

    const filtered = attacks.filter((a: Record<string, unknown>) => a.technique === techniqueId);
    if (filtered.length === 0) return `No attacks found for technique ${techniqueId}`;

    const detected = filtered.filter((a: Record<string, unknown>) => a.result === 'blocked').length;
    const total = filtered.length;
    const wazuhRules = [...new Set(filtered.map((a: Record<string, unknown>) => a.wazuhRuleExpected).filter(Boolean))];

    return `Technique ${techniqueId}: ${total} attempts, ${detected} blocked (${Math.round(detected / total * 100)}% detection rate). Expected Wazuh rules: ${wazuhRules.join(', ') || 'none specified'}`;
  }

  // Tool 4: Recommendation engine
  private toolRecommendation(args: Record<string, string>): string {
    const finding = args.finding?.toLowerCase() ?? '';

    const recommendations: Record<string, string> = {
      'sql injection': '1. Use parameterized queries/prepared statements\n2. Implement input validation (allowlist approach)\n3. Deploy WAF rules for SQLi patterns\n4. Enable database auditing\n5. Apply principle of least privilege for DB accounts',
      'command injection': '1. Avoid shell execution with user input\n2. Use allowlisted command arguments\n3. Implement input sanitization\n4. Run applications in sandboxed containers\n5. Enable process auditing',
      'weak password': '1. Enforce minimum 14-character passwords\n2. Implement MFA for all accounts\n3. Deploy password policy via GPO\n4. Use LAPS for local admin passwords\n5. Monitor for password spraying (Wazuh rule 60122)',
      'kerberoast': '1. Use AES encryption for service accounts (disable RC4)\n2. Set service account passwords to 25+ characters\n3. Use gMSA where possible\n4. Monitor for TGS-REQ anomalies (Wazuh rule 4769)\n5. Restrict SPN assignments',
      'lateral movement': '1. Implement network segmentation (VLANs)\n2. Deploy host-based firewall rules\n3. Use tiered admin model\n4. Enable Windows Credential Guard\n5. Monitor for PsExec/WinRM usage (Wazuh rules 92600-92602)',
      'privilege escalation': '1. Remove unnecessary local admin rights\n2. Deploy LAPS\n3. Enable UAC and Credential Guard\n4. Audit scheduled tasks and services\n5. Monitor for token manipulation (Wazuh rule 4672)',
    };

    for (const [key, rec] of Object.entries(recommendations)) {
      if (finding.includes(key)) return rec;
    }

    return `Generic remediation for "${finding}":\n1. Apply defense-in-depth principles\n2. Enable logging and monitoring\n3. Conduct regular vulnerability assessments\n4. Implement network segmentation\n5. Follow CIS benchmarks for hardening`;
  }
}
