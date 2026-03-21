// Attack planner -- LLM reads graph state and generates agent roster + attack plan
// Adapted from MiroFish simulation_config_generator + oasis_profile_generator patterns
// v3: Closed-loop planner with budget tracking and fallback deterministic planning

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { runAgent } from '../ai/claude-executor.js';
import { loadPrompt } from '../services/prompt-manager.js';
import { AttackGraphService } from '../services/attack-graph.js';
import { AGENT_TEMPLATE_LIBRARY } from '../session-manager.js';
import { OpenMemoryClient } from './openmemory-client.js';
import type {
  ActionPlan,
  AgentProfile,
  BudgetState,
  RoundResult,
  WraithV3Config,
} from '../types/index.js';

export class AttackPlanner {
  async generateInitialPlan(
    graphService: AttackGraphService,
    config: WraithV3Config,
  ): Promise<ActionPlan> {
    const budget = this.getBudgetState(config, 0, 0);
    return this.plan(graphService, [], budget, config);
  }

  async replan(
    graphService: AttackGraphService,
    history: RoundResult[],
    budget: BudgetState,
    config: WraithV3Config,
  ): Promise<ActionPlan> {
    return this.plan(graphService, history, budget, config);
  }

  resolveDependencies(agents: AgentProfile[]): AgentProfile[][] {
    // Topological sort into executable batches
    const batches: AgentProfile[][] = [];
    const resolved = new Set<string>();
    let remaining = [...agents];

    while (remaining.length > 0) {
      const batch: AgentProfile[] = [];
      const stillRemaining: AgentProfile[] = [];

      for (const agent of remaining) {
        const depsResolved = agent.depends_on.every(dep => resolved.has(dep));
        if (depsResolved) {
          batch.push(agent);
        } else {
          stillRemaining.push(agent);
        }
      }

      if (batch.length === 0) {
        // Circular dependency or missing deps -- dump all remaining into one batch
        console.warn('[planner] Unresolvable dependencies detected -- forcing batch');
        batches.push(stillRemaining);
        break;
      }

      // Sort batch by priority (highest first)
      batch.sort((a, b) => b.priority - a.priority);
      batches.push(batch);

      for (const agent of batch) {
        resolved.add(agent.id);
      }
      remaining = stillRemaining;
    }

    return batches;
  }

  getBudgetState(config: WraithV3Config, roundsUsed: number, agentsSpawned: number): BudgetState {
    const planning = config.planning ?? {
      max_rounds: 10,
      max_total_agents: 30,
      max_concurrent_agents: 3,
    };
    return {
      max_rounds: planning.max_rounds,
      rounds_used: roundsUsed,
      max_total_agents: planning.max_total_agents,
      agents_spawned: agentsSpawned,
      max_concurrent: planning.max_concurrent_agents,
    };
  }

  private async plan(
    graphService: AttackGraphService,
    history: RoundResult[],
    budget: BudgetState,
    config: WraithV3Config,
  ): Promise<ActionPlan> {
    const round = budget.rounds_used + 1;
    const graphSummary = graphService.getDetailedSummary();
    const templates = Object.keys(AGENT_TEMPLATE_LIBRARY).join(', ');
    const objective = config.planning?.objective ?? 'full_assessment';

    // Format round history
    const historyStr = history.length === 0
      ? 'No previous rounds.'
      : history.map(r => {
          const agents = r.agent_results.map(
            a => `  - ${a.agent_id}: ${a.success ? 'SUCCESS' : 'FAILED'} (${a.turns_used} turns, ${a.duration_ms}ms) -- ${a.result_summary.substring(0, 100)}`,
          ).join('\n');
          return `### Round ${r.round}\n${agents}`;
        }).join('\n\n');

    // v3.1.0 E2: Feed credential state to planner
    const logDir = config.output.log_dir;
    let credentialState = 'No credentials discovered yet.';
    const credsPath = join(logDir, 'credentials.json');
    if (existsSync(credsPath)) {
      try {
        const creds = JSON.parse(readFileSync(credsPath, 'utf-8'));
        if (Array.isArray(creds) && creds.length > 0) {
          credentialState = `${creds.length} credentials:\n${creds.map((c: Record<string, string>) => `- ${c.username}: scope=${c.scope}, source=${c.source}`).join('\n')}`;
        }
      } catch { /* skip */ }
    }

    // v3.1.0 C3: Query OpenMemory for cross-run context
    let omContext = '';
    try {
      const om = new OpenMemoryClient();
      omContext = await om.query(`wraith attack findings for ${config.target.domain}`);
    } catch { omContext = 'OpenMemory unavailable.'; }

    try {
      const prompt = await loadPrompt('planner', {
        round: String(round),
        objective,
        stealth_mode: String(config.planning?.stealth_mode ?? false),
        budget_rounds: String(budget.max_rounds - budget.rounds_used),
        budget_agents: String(budget.max_total_agents - budget.agents_spawned),
        graph_summary: graphSummary,
        available_templates: templates,
        round_history: historyStr,
        max_concurrent: String(budget.max_concurrent),
        credential_state: credentialState,
        openmemory_context: omContext,
      });

      // v3.1.0 E4: Retry JSON parse before fallback (BUG-13 fix)
      let plan: ActionPlan | null = null;
      for (let attempt = 0; attempt < 2; attempt++) {
        const result = await runAgent(prompt, 'planner', 'medium', {}, 20);  // v3.2.0 BUG-21: increased from 10
        if (!result.success || !result.result) continue;
        try {
          plan = this.extractJSON(result.result) as ActionPlan;
          plan.round = round;
          break;
        } catch {
          if (attempt === 0) console.log('[planner] JSON parse failed, retrying...');
        }
      }
      if (!plan) {
        console.warn('[planner] LLM planning failed after 2 attempts -- deterministic fallback');
        return this.deterministicPlan(graphService, round, budget, config);
      }

      // Validate: cap agents at budget
      const maxNew = budget.max_total_agents - budget.agents_spawned;
      if (plan.agents_to_spawn.length > maxNew) {
        plan.agents_to_spawn = plan.agents_to_spawn.slice(0, maxNew);
      }
      if (plan.agents_to_spawn.length > budget.max_concurrent) {
        // Keep top priority agents
        plan.agents_to_spawn.sort((a, b) => b.priority - a.priority);
        plan.agents_to_spawn = plan.agents_to_spawn.slice(0, budget.max_concurrent);
      }

      return plan;
    } catch (err) {
      console.warn(`[planner] Error during planning: ${err} -- using deterministic fallback`);
      return this.deterministicPlan(graphService, round, budget, config);
    }
  }

  private deterministicPlan(
    graphService: AttackGraphService,
    round: number,
    budget: BudgetState,
    config: WraithV3Config,
  ): ActionPlan {
    const viableVectors = graphService.getViableVectors();
    const agents: AgentProfile[] = [];
    const maxAgents = Math.min(
      budget.max_concurrent,
      budget.max_total_agents - budget.agents_spawned,
    );
    const spawnedCombos = new Set<string>();

    // Part 1: Vector-based agents (existing logic)
    for (const target of viableVectors) {
      if (agents.length >= maxAgents) break;

      for (const vector of target.vectors) {
        if (agents.length >= maxAgents) break;

        const template = this.vectorToTemplate(vector);
        if (!template) continue;

        const combo = `${template}-${target.ip}`;
        if (spawnedCombos.has(combo)) continue;
        spawnedCombos.add(combo);

        const lib = AGENT_TEMPLATE_LIBRARY[template];
        if (!lib) continue;

        agents.push({
          id: `${template}-r${round}-${target.ip}`,
          technique: this.vectorToTechnique(vector),
          technique_name: vector,
          target_ip: target.ip,
          prompt_template: template,
          model_tier: lib.defaultTier,
          turn_budget: lib.defaultTurnBudget,
          timeout_sec: lib.defaultTimeout,
          priority: target.priority,
          stealth_level: config.planning?.stealth_mode ? 'quiet' : 'moderate',
          depends_on: [],
          context_vars: {
            round_context: `Deterministic plan, round ${round}. Target: ${target.host} (${target.ip}).`,
          },
        });
      }
    }

    // Part 2: Credential-driven agents (v3.3.0 BUG-25/28/29)
    if (agents.length < maxAgents) {
      const credAgents = this.credentialDrivenAgents(graphService, round, config, spawnedCombos);
      for (const agent of credAgents) {
        if (agents.length >= maxAgents) break;
        agents.push(agent);
      }
    }

    const credDriven = agents.filter(a => ['kerberoast', 'lateral', 'privesc'].includes(a.prompt_template)).length;
    const objectiveStatus = agents.length === 0
      ? (viableVectors.length === 0 ? 'achieved' : 'blocked')
      : budget.rounds_used >= budget.max_rounds
        ? 'budget_exhausted'
        : 'in_progress';

    return {
      round,
      agents_to_spawn: agents,
      agents_to_skip: [],
      objective_status: objectiveStatus,
      reasoning: `Deterministic fallback: ${agents.length} agents (${credDriven} credential-driven) for ${viableVectors.length} targets.`,
      next_milestone: agents.length > 0
        ? `Execute ${agents[0].technique_name} against ${agents[0].target_ip}`
        : 'No viable vectors remaining',
    };
  }

  // v3.3.0: Spawn kerberoast/lateral/privesc when credentials exist (BUG-25/28/29)
  private credentialDrivenAgents(
    graphService: AttackGraphService,
    round: number,
    config: WraithV3Config,
    spawnedCombos: Set<string>,
  ): AgentProfile[] {
    const agents: AgentProfile[] = [];
    const logDir = config.output.log_dir;
    const snapshot = graphService.getGraphSnapshot();
    const nodes = Object.values(snapshot.nodes);

    // Load credential state
    let creds: Array<Record<string, unknown>> = [];
    const credsPath = join(logDir, 'credentials.json');
    if (existsSync(credsPath)) {
      try {
        creds = JSON.parse(readFileSync(credsPath, 'utf-8'));
      } catch { /* skip */ }
    }
    if (!Array.isArray(creds) || creds.length === 0) return agents;

    const hasDomainCreds = creds.some(c => c.scope === 'domain');
    const hasAdminAccess = nodes.some(n => n.access_level === 'admin' || n.access_level === 'system');
    const stealth = config.planning?.stealth_mode ? 'quiet' as const : 'moderate' as const;

    // Rule 1: Domain creds + port 88 open -> kerberoast
    if (hasDomainCreds) {
      const kerberosHost = nodes.find(n =>
        n.services.some(s => s.includes('88') || s.includes('kerberos')) &&
        n.status !== 'blocked',
      );
      if (kerberosHost) {
        const combo = `kerberoast-${kerberosHost.ip}`;
        if (!spawnedCombos.has(combo)) {
          spawnedCombos.add(combo);
          const lib = AGENT_TEMPLATE_LIBRARY['kerberoast'];
          agents.push({
            id: `kerberoast-r${round}-${kerberosHost.ip}`,
            technique: 'T1558.003',
            technique_name: 'Kerberoasting',
            target_ip: kerberosHost.ip,
            prompt_template: 'kerberoast',
            model_tier: lib.defaultTier,
            turn_budget: lib.defaultTurnBudget,
            timeout_sec: lib.defaultTimeout,
            priority: 8,
            stealth_level: stealth,
            depends_on: [],
            context_vars: {
              round_context: `Credential-driven: domain creds available, Kerberos service on ${kerberosHost.ip}.`,
            },
          });
        }
      }
    }

    // Rule 2: Any creds + multiple hosts with SMB/WinRM -> lateral
    if (creds.length > 0 && nodes.filter(n => n.status !== 'blocked').length > 1) {
      const lateralTarget = nodes.find(n =>
        n.status !== 'blocked' &&
        n.services.some(s => s.includes('445') || s.includes('5985') || s.includes('smb') || s.includes('winrm')),
      );
      if (lateralTarget) {
        const combo = `lateral-${lateralTarget.ip}`;
        if (!spawnedCombos.has(combo)) {
          spawnedCombos.add(combo);
          const lib = AGENT_TEMPLATE_LIBRARY['lateral'];
          agents.push({
            id: `lateral-r${round}-${lateralTarget.ip}`,
            technique: 'T1021.002',
            technique_name: 'Remote Service Access',
            target_ip: lateralTarget.ip,
            prompt_template: 'lateral',
            model_tier: lib.defaultTier,
            turn_budget: lib.defaultTurnBudget,
            timeout_sec: lib.defaultTimeout,
            priority: 7,
            stealth_level: stealth,
            depends_on: [],
            context_vars: {
              round_context: `Credential-driven: ${creds.length} credentials available, testing reuse against ${lateralTarget.ip}.`,
            },
          });
        }
      }
    }

    // Rule 3: Admin access on any host -> privesc
    if (hasAdminAccess) {
      const adminHost = nodes.find(n =>
        (n.access_level === 'admin' || n.access_level === 'system') &&
        n.status !== 'blocked',
      );
      if (adminHost) {
        const combo = `privesc-${adminHost.ip}`;
        if (!spawnedCombos.has(combo)) {
          spawnedCombos.add(combo);
          const lib = AGENT_TEMPLATE_LIBRARY['privesc'];
          agents.push({
            id: `privesc-r${round}-${adminHost.ip}`,
            technique: 'T1068',
            technique_name: 'Privilege Escalation',
            target_ip: adminHost.ip,
            prompt_template: 'privesc',
            model_tier: lib.defaultTier,
            turn_budget: lib.defaultTurnBudget,
            timeout_sec: lib.defaultTimeout,
            priority: 9,
            stealth_level: stealth,
            depends_on: [],
            context_vars: {
              round_context: `Credential-driven: admin access on ${adminHost.ip}, escalating.`,
            },
          });
        }
      }
    }

    return agents;
  }

  private vectorToTemplate(vector: string): string | null {
    // v3.1.0 E1: Expanded from 15 to 30+ entries
    const map: Record<string, string> = {
      // Web exploitation
      'web-app': 'sqli', 'sqli': 'sqli', 'cmdi': 'cmdi', 'auth-bypass': 'auth-attack',
      'dvwa': 'sqli', 'dvwa-sqli': 'sqli', 'dvwa-cmdi': 'cmdi',
      'dvwa-fileupload-rce': 'cmdi', 'dvwa-rfi': 'cmdi', 'php-rce': 'cmdi',
      'xampp-misconfiguration': 'auth-attack', 'mariadb-direct-access': 'sqli',
      'web-admin': 'auth-attack', 'pfsense-webgui-bruteforce': 'auth-attack',
      // Credential attacks
      'kerberoast': 'kerberoast', 'asreproast': 'kerberoast',
      'smb-brute': 'bruteforce', 'rdp-brute': 'bruteforce', 'rdp-bruteforce': 'bruteforce',
      'ssh-brute': 'bruteforce', 'ssh-bruteforce': 'bruteforce',
      'brute-force': 'bruteforce', 'password-spray': 'bruteforce',
      'rid-bruteforce': 'bruteforce',
      // Lateral movement
      'smb-relay': 'lateral', 'smb-lateral': 'lateral',
      'psexec': 'lateral', 'winrm': 'lateral',
      'ntlm-relay': 'lateral', 'impacket-attacks': 'lateral',
      // Privilege escalation
      'impacket-secretsdump-with-creds': 'privesc',
      // Recon / enumeration
      'port-scan': 'recon', 'service-enum': 'recon',
      'ldap-enum': 'recon', 'smb-enum': 'recon', 'nat-traversal': 'recon',
      // Automated scanning
      'nuclei-scan': 'nuclei',
    };
    return map[vector] ?? null;
  }

  private vectorToTechnique(vector: string): string {
    const map: Record<string, string> = {
      'web-app': 'T1190',
      'sqli': 'T1190',
      'cmdi': 'T1059',
      'auth-bypass': 'T1078',
      'dvwa': 'T1190',
      'smb-relay': 'T1021.002',
      'smb-brute': 'T1110',
      'psexec': 'T1021.002',
      'winrm': 'T1021.006',
      'rdp-brute': 'T1110',
      'kerberoast': 'T1558.003',
      'asreproast': 'T1558.004',
      'ldap-enum': 'T1087',
      'ssh-brute': 'T1110',
    };
    return map[vector] ?? 'T0000';
  }

  private extractJSON(text: string): unknown {
    const fenced = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
    const jsonStr = fenced ? fenced[1] : text;
    const start = jsonStr.indexOf('{');
    const end = jsonStr.lastIndexOf('}');
    if (start === -1 || end === -1) throw new Error('No JSON object found in planner output');
    return JSON.parse(jsonStr.substring(start, end + 1));
  }
}
