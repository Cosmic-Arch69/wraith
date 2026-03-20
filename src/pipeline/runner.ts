// Wraith v3 Adaptive Pipeline Runner
// Replaces static DAG with closed-loop: Config -> Recon -> Ontology -> Graph -> Plan -> Attack Loop -> Report
// RUN-5 fixes: exponential backoff, concurrency limiter, failure-aware replanning

import { readFileSync, mkdirSync, writeFileSync, existsSync, appendFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import yaml from 'js-yaml';
import { startAgent } from '../ai/claude-executor.js';
import { loadPromptWithProfile } from '../services/prompt-manager.js';
import { processManager } from '../services/process-manager.js';
import { PotWatcher } from '../services/pot-watcher.js';
import { CredentialStore } from '../services/credential-store.js';
import { AttackGraphService } from '../services/attack-graph.js';
import { ResponderManager } from '../services/responder-manager.js';
import { ConcurrencyLimiter } from '../utils/concurrency.js';
import { OntologyGenerator } from './ontology-generator.js';
import { GraphBuilder } from './graph-builder.js';
import { Evaluator } from './evaluator.js';
import { AttackPlanner } from './planner.js';
import { ReportGenerator } from './report-react.js';
import type {
  AgentProfile,
  AgentRoundResult,
  RoundResult,
  WraithV3Config,
} from '../types/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const MCP_SERVER_PATH = join(__dirname, '..', 'mcp', 'server.js');

// Load all memory files for agent context injection
function loadMemoryContext(logDir: string): string {
  const memDir = join(logDir, 'memory');
  if (!existsSync(memDir)) return '';
  try {
    const files = readdirSync(memDir).filter(f => f.endsWith('.md'));
    if (files.length === 0) return '';
    const contents = files.map(f => {
      const name = f.replace('.md', '');
      return `### ${name}\n${readFileSync(join(memDir, f), 'utf-8').trim()}`;
    }).join('\n\n');
    return `## Session Memory (auto-injected)\n\n${contents}\n\n---\n\n`;
  } catch {
    return '';
  }
}

// BUG-1 fix: Validate recon output (ported from runner-legacy.ts validatePhaseOutput)
function validateReconOutput(logDir: string): { valid: boolean; missing: string[] } {
  const missing: string[] = [];
  const deliverable = join(logDir, 'recon_deliverable.json');

  if (!existsSync(deliverable)) {
    missing.push('recon_deliverable.json does not exist');
  } else {
    const content = readFileSync(deliverable, 'utf-8');
    if (content.length < 50) {
      missing.push(`recon_deliverable.json is too small (${content.length} chars, expected >= 50)`);
    } else {
      try {
        const data = JSON.parse(content);
        if (!data.hosts && !data.live_hosts) {
          missing.push('recon_deliverable.json missing hosts data');
        }
      } catch {
        missing.push('recon_deliverable.json is not valid JSON');
      }
    }
  }

  return { valid: missing.length === 0, missing };
}

async function spawnAgent(
  profile: AgentProfile,
  config: WraithV3Config,
  logDir: string,
): Promise<AgentRoundResult> {
  const start = Date.now();
  const agentId = profile.id;

  console.log(`  [spawn] ${agentId} (${profile.technique_name} -> ${profile.target_ip})`);

  // Build base vars from config
  const firstWebHost = config.target.hosts.find(h => h.web_url);
  const baseVars: Record<string, string> = {
    domain: config.target.domain,
    dc: config.target.dc,
    hosts: JSON.stringify(config.target.hosts),
    credentials: JSON.stringify(config.target.credentials),
    logDir,
    randomize: String(config.attack.randomize),
    delayMin: String(config.attack.delay_min_sec),
    delayMax: String(config.attack.delay_max_sec),
    web_host: firstWebHost?.ip ?? '',
    web_url: firstWebHost?.web_url ?? '',
    domain_user: config.target.credentials.domain_user,
    domain_pass: config.target.credentials.domain_pass,
    web_dvwa_user: config.target.credentials.web_dvwa_user ?? 'admin',
    web_dvwa_pass: config.target.credentials.web_dvwa_pass ?? 'password',
    wan_ip: config.engagement?.wan_ip ?? '',
    engagement_type: config.engagement?.type ?? 'internal',
  };

  // Load prompt with profile vars
  const prompt = await loadPromptWithProfile(profile.prompt_template, profile, baseVars);

  // Inject memory context
  const memory = loadMemoryContext(logDir);
  const fullPrompt = [memory, prompt].filter(Boolean).join('\n');

  // Setup MCP servers
  const mcpServers = {
    'wraith-tools': {
      command: 'node',
      args: [MCP_SERVER_PATH],
      env: {
        WRAITH_LOG_DIR: logDir,
        WRAITH_AGENT_NAME: agentId,
      },
    },
  };

  // Wall-clock timeout with cancellation (BUG-7 fix)
  const timeoutPromise = new Promise<null>(resolve =>
    setTimeout(() => resolve(null), profile.timeout_sec * 1000),
  );

  const handle = startAgent(
    fullPrompt,
    agentId,
    profile.model_tier,
    mcpServers,
    profile.turn_budget,
  );

  const result = await Promise.race([handle.promise, timeoutPromise]);
  const duration = Date.now() - start;

  if (result === null) {
    // Timeout -- actually kill the SDK process
    handle.abort();
    console.log(`  [timeout] ${agentId} killed after ${profile.timeout_sec}s`);
    return {
      agent_id: agentId,
      success: false,
      result_summary: `TIMEOUT after ${profile.timeout_sec}s`,
      duration_ms: duration,
      turns_used: 0,
      evidence_files: [],
      credentials_found: 0,
      vectors_opened: [],
      vectors_blocked: [],
    };
  }

  // Scan for evidence files produced by this agent
  const evidenceFiles: string[] = [];
  const possibleFiles = [
    `${profile.prompt_template}_evidence.md`,
    `${profile.prompt_template}_deliverable.json`,
  ];
  for (const f of possibleFiles) {
    if (existsSync(join(logDir, f))) evidenceFiles.push(f);
  }

  console.log(`  [done] ${agentId}: ${result.success ? 'SUCCESS' : 'FAILED'} (${result.turns ?? 0} turns, ${duration}ms)`);

  return {
    agent_id: agentId,
    success: result.success,
    result_summary: result.result?.substring(0, 500) ?? 'No output',
    duration_ms: duration,
    turns_used: result.turns ?? 0,
    evidence_files: evidenceFiles,
    credentials_found: 0,
    vectors_opened: [],
    vectors_blocked: result.success ? [] : [profile.technique_name],
  };
}

export async function runPipeline(configPath: string): Promise<void> {
  // 1. Load config
  const config = yaml.load(readFileSync(configPath, 'utf-8')) as WraithV3Config;
  const logDir = config.output.log_dir;
  mkdirSync(logDir, { recursive: true });
  mkdirSync(join(logDir, 'memory'), { recursive: true });

  const planning = config.planning ?? {
    max_rounds: 10,
    max_total_agents: 30,
    max_concurrent_agents: 3,
  };

  console.log(`\n  Wraith v3.0.0 -- Adaptive Pipeline`);
  console.log(`  Target: ${config.target.domain} (${config.target.dc})`);
  console.log(`  Hosts:  ${config.target.hosts.map(h => h.ip).join(', ')}`);
  console.log(`  Budget: ${planning.max_rounds} rounds, ${planning.max_total_agents} agents, ${planning.max_concurrent_agents} concurrent`);
  console.log(`  Objective: ${planning.objective ?? 'full_assessment'}`);
  console.log(`  Config: ${configPath}\n`);

  // 2. Install signal handlers, init services
  processManager.installSignalHandlers();
  const potWatcher = new PotWatcher(logDir);
  potWatcher.start();
  const credStore = new CredentialStore(logDir);
  const attackGraph = new AttackGraphService(logDir);

  attackGraph.setEngagement(
    config.engagement?.type ?? 'internal',
    config.engagement?.wan_ip,
  );

  // Seed credential store
  if (config.target.credentials.domain_user && config.target.credentials.domain_pass) {
    credStore.add({
      username: config.target.credentials.domain_user,
      password: config.target.credentials.domain_pass,
      source: 'config',
      scope: 'domain',
      hosts_valid: [],
      hosts_failed: [],
      protocol_valid: [],
      protocol_failed: [],
    });
  }

  // Seed graph with known hosts (BUG-4/5 fix: guard empty DC)
  for (const host of config.target.hosts) {
    attackGraph.initNode(host.ip, host.name);
  }
  if (config.target.dc) {
    attackGraph.initNode(config.target.dc, 'DC');
  }

  // 3. Start Responder (if internal engagement)
  const networkInterface = config.engagement?.network_interface ?? 'eth0';
  const responderManager = new ResponderManager(logDir);
  if (config.engagement?.type !== 'external') {
    responderManager.start(networkInterface);
    if (responderManager.getStartError()) {
      console.warn(`[pipeline] Responder failed: ${responderManager.getStartError()?.message} -- continuing`);
    }
  }

  // Seed session memory
  writeFileSync(join(logDir, 'memory', 'session.md'), [
    `# Wraith v3 Session`,
    `Started: ${new Date().toISOString()}`,
    `Mode: Adaptive Pipeline`,
    ``,
    `## Target`,
    `- Domain: ${config.target.domain}`,
    `- DC: ${config.target.dc}`,
    `- Hosts: ${config.target.hosts.map(h => `${h.ip} (${h.name})`).join(', ')}`,
    ``,
    `## Status`,
    `- Round: 0 (initializing)`,
    `- SOAR blocks: none yet`,
    `- Cracked credentials: none yet`,
  ].join('\n'));

  // =====================================================
  // 4. RECON (fixed, always first)
  // =====================================================
  console.log('[pipeline] Phase: RECON');
  const reconProfile: AgentProfile = {
    id: 'recon-r0',
    technique: 'T1046',
    technique_name: 'Network Scanning',
    target_ip: config.target.dc || config.target.hosts[0]?.ip || '',  // BUG-3 fix: fallback to first host in external mode
    prompt_template: 'recon',
    model_tier: 'medium',
    turn_budget: 100,
    timeout_sec: 900,
    priority: 10,
    stealth_level: 'loud',
    depends_on: [],
    context_vars: { round_context: 'Initial reconnaissance. Map all hosts, services, and attack surface.' },
  };

  const reconResult = await spawnAgent(reconProfile, config, logDir);
  if (!reconResult.success) {
    potWatcher.stop();
    responderManager.stop();
    throw new Error('Recon failed -- cannot proceed without target map');
  }

  // BUG-1 fix: Validate recon output -- retry if deliverable missing
  const reconValidation = validateReconOutput(logDir);
  if (!reconValidation.valid) {
    console.log(`[pipeline] Recon output invalid: ${reconValidation.missing.join(', ')} -- retrying`);
    const retryProfile: AgentProfile = {
      ...reconProfile,
      id: 'recon-r0-retry',
      context_vars: {
        round_context: `RETRY: Previous recon reported success but produced NO deliverable file. You MUST run nmap against all target hosts and write the results to recon_deliverable.json. Missing: ${reconValidation.missing.join(', ')}. Target hosts: ${config.target.hosts.map(h => h.ip).join(', ')}`,
      },
    };
    await spawnAgent(retryProfile, config, logDir);
    const recheck = validateReconOutput(logDir);
    if (!recheck.valid) {
      console.warn(`[pipeline] Recon retry also failed: ${recheck.missing.join(', ')} -- continuing with config-only graph`);
    }
  }

  // =====================================================
  // 5. ONTOLOGY (LLM generates schema from recon)
  // =====================================================
  console.log('[pipeline] Phase: ONTOLOGY');
  const ontologyGen = new OntologyGenerator();
  let reconData = '';
  const reconPath = join(logDir, 'recon_deliverable.json');
  if (existsSync(reconPath)) {
    reconData = readFileSync(reconPath, 'utf-8');
  }
  const ontology = await ontologyGen.generate(reconData, config);
  writeFileSync(join(logDir, 'ontology.json'), JSON.stringify(ontology, null, 2));
  console.log(`[pipeline] Ontology: ${ontology.entity_types.length} entity types, ${ontology.edge_types.length} edge types`);

  // =====================================================
  // 6. GRAPH (build typed graph from recon + ontology)
  // =====================================================
  console.log('[pipeline] Phase: GRAPH BUILD');
  const graphBuilder = new GraphBuilder();
  graphBuilder.buildFromRecon(logDir, ontology, attackGraph, config);

  // =====================================================
  // 7. ATTACK LOOP (plan -> spawn -> evaluate -> replan)
  // =====================================================
  console.log('[pipeline] Phase: ATTACK LOOP');
  const planner = new AttackPlanner();
  const evaluator = new Evaluator();
  const limiter = new ConcurrencyLimiter(planning.max_concurrent_agents);
  const history: RoundResult[] = [];
  let agentsSpawned = 1; // recon counted

  for (let round = 1; round <= planning.max_rounds; round++) {
    const budget = planner.getBudgetState(config, round - 1, agentsSpawned);

    console.log(`\n[pipeline] === Round ${round}/${planning.max_rounds} (agents: ${agentsSpawned}/${planning.max_total_agents}) ===`);

    // Plan
    const plan = round === 1
      ? await planner.generateInitialPlan(attackGraph, config)
      : await planner.replan(attackGraph, history, budget, config);

    console.log(`[planner] Status: ${plan.objective_status} | Agents: ${plan.agents_to_spawn.length} | ${plan.reasoning}`);

    // Check termination
    if (plan.objective_status === 'achieved') {
      console.log('[pipeline] Objective achieved!');
      break;
    }
    if (plan.objective_status === 'budget_exhausted') {
      console.log('[pipeline] Budget exhausted.');
      break;
    }
    if (plan.objective_status === 'blocked') {
      console.log('[pipeline] All vectors blocked.');
      break;
    }
    if (plan.agents_to_spawn.length === 0) {
      console.log('[pipeline] No agents to spawn -- ending.');
      break;
    }

    // Resolve dependencies into batches
    const batches = planner.resolveDependencies(plan.agents_to_spawn);
    const roundStarted = new Date().toISOString();
    const roundResults: AgentRoundResult[] = [];
    let roundDelta = {
      nodes_added: [] as string[],
      nodes_updated: [] as string[],
      edges_added: 0,
      vectors_opened: [] as string[],
      vectors_closed: [] as string[],
      credentials_gained: 0,
      access_levels_changed: [] as Array<{ ip: string; from: string; to: string }>,
    };

    for (const batch of batches) {
      console.log(`  [batch] ${batch.map(a => a.id).join(', ')}`);

      const results = await limiter.runBatch(
        batch.map(profile => () => spawnAgent(profile, config, logDir)),
      );

      for (let i = 0; i < results.length; i++) {
        const settled = results[i];
        const profile = batch[i];
        agentsSpawned++;

        let agentResult: AgentRoundResult;
        if (settled.status === 'fulfilled') {
          agentResult = settled.value;
        } else {
          agentResult = {
            agent_id: profile.id,
            success: false,
            result_summary: `Error: ${settled.reason}`,
            duration_ms: 0,
            turns_used: 0,
            evidence_files: [],
            credentials_found: 0,
            vectors_opened: [],
            vectors_blocked: [profile.technique_name],
          };
        }

        // Evaluate result and update graph
        const delta = evaluator.evaluate(agentResult, logDir, attackGraph, credStore);
        roundResults.push(agentResult);

        // Merge deltas
        roundDelta.nodes_added.push(...delta.nodes_added);
        roundDelta.nodes_updated.push(...delta.nodes_updated);
        roundDelta.edges_added += delta.edges_added;
        roundDelta.vectors_opened.push(...delta.vectors_opened);
        roundDelta.vectors_closed.push(...delta.vectors_closed);
        roundDelta.credentials_gained += delta.credentials_gained;
        roundDelta.access_levels_changed.push(...delta.access_levels_changed);
      }
    }

    // Record round
    const roundResult: RoundResult = {
      round,
      started_at: roundStarted,
      completed_at: new Date().toISOString(),
      agent_results: roundResults,
      graph_delta: roundDelta,
    };
    history.push(roundResult);

    // Update session memory
    const succeeded = roundResults.filter(r => r.success).length;
    const failed = roundResults.length - succeeded;
    appendFileSync(
      join(logDir, 'memory', 'session.md'),
      `\n- [Round ${round}] ${succeeded} succeeded, ${failed} failed. Vectors opened: ${roundDelta.vectors_opened.length}, closed: ${roundDelta.vectors_closed.length}. Creds: +${roundDelta.credentials_gained}\n`,
    );

    // Check objective after evaluation
    const objectiveMet = evaluator.checkObjective(
      attackGraph.getGraphSnapshot(),
      config.planning?.objective ?? 'full_assessment',
    );
    if (objectiveMet) {
      console.log('[pipeline] Objective achieved after evaluation!');
      break;
    }
  }

  // =====================================================
  // 8. REPORT (ReACT agent)
  // =====================================================
  console.log('\n[pipeline] Phase: REPORT');
  const reportGen = new ReportGenerator();
  const report = await reportGen.generateReport(
    attackGraph.getGraphSnapshot(),
    history,
    logDir,
    config,
  );
  writeFileSync(join(logDir, 'pentest_report.md'), report);
  console.log(`[pipeline] Report written to ${logDir}/pentest_report.md`);

  // Save round history
  writeFileSync(join(logDir, 'round_history.json'), JSON.stringify(history, null, 2));

  // 9. Cleanup
  potWatcher.stop();
  responderManager.stop();

  const totalSucceeded = history.reduce((s, r) => s + r.agent_results.filter(a => a.success).length, 0);
  const totalFailed = history.reduce((s, r) => s + r.agent_results.filter(a => !a.success).length, 0);

  console.log(`\n  Wraith v3 complete.`);
  console.log(`  Rounds: ${history.length} | Agents: ${agentsSpawned} (${totalSucceeded} succeeded, ${totalFailed} failed)`);
  console.log(`  Report: ${logDir}/pentest_report.md\n`);
}
