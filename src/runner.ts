// Wraith v2-clean direct runner -- no Temporal required
// Executes the agent DAG in-process: sequential phases + parallel where safe
// v2-clean: bug fixes only (phase validation, turn budgets, process management, pot-watching)
// NO Agents of Chaos hardening (no identity boundaries, no output sanitization, no proportionality rules)

import { readFileSync, mkdirSync, writeFileSync, appendFileSync, existsSync, readdirSync, renameSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import yaml from 'js-yaml';
import { runAgent as claudeRun } from './ai/claude-executor.js';
import type { ExecutorResult } from './ai/claude-executor.js';
import type { AgentName, WraithConfig } from './types/index.js';
import { AGENTS, getExecutionPhases } from './session-manager.js';
import { loadPrompt } from './services/prompt-manager.js';
import { processManager } from './services/process-manager.js';
import { PotWatcher } from './services/pot-watcher.js';
import { CredentialStore } from './services/credential-store.js';
import { AttackGraphService } from './services/attack-graph.js';
import { ResponderManager } from './services/responder-manager.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const MCP_SERVER_PATH = join(__dirname, 'mcp', 'server.js');

// v2: Per-agent turn budgets -- prevent context exhaustion + runaway loops
// v2.1: Partial record -- osint-recon added by T6 integration
const TURN_BUDGETS: Partial<Record<AgentName, number>> & Record<string, number> = {
  'osint-recon': 60,
  recon: 100,
  sqli: 80,
  cmdi: 80,
  'auth-attack': 80,
  kerberoast: 120,
  bruteforce: 100,
  lateral: 150,
  privesc: 200,
  report: 100,  // P5: increased from 50 -- report_input.json is pre-structured but still takes turns to format
};

// v2.1 F4: Default wall-clock timeouts per agent (seconds)
const DEFAULT_TIMEOUTS: Record<string, number> = {
  'osint-recon': 600, recon: 900, sqli: 600, cmdi: 600,
  'auth-attack': 600, kerberoast: 600, bruteforce: 900,
  lateral: 1200, privesc: 1200, report: 600,
};

// Read all memory files and inject them into the prompt -- vault pattern.
// Memory is always present at agent start, no tool call required.
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
    return `## Session Memory (auto-injected -- always current)\n\n${contents}\n\n---\n\n`;
  } catch {
    return '';
  }
}

// v2 (Bug 10): Validate that an agent actually produced its expected output
function validatePhaseOutput(agentName: AgentName, logDir: string): { valid: boolean; missing: string[] } {
  const missing: string[] = [];
  const memDir = join(logDir, 'memory');

  const checkFile = (path: string, minSize: number, label: string) => {
    if (!existsSync(path)) {
      missing.push(`${label} does not exist`);
    } else {
      const content = readFileSync(path, 'utf-8');
      if (content.length < minSize) {
        missing.push(`${label} is too small (${content.length} chars, expected >= ${minSize})`);
      }
    }
  };

  switch (agentName) {
    case 'recon': {
      const deliverable = join(logDir, 'recon_deliverable.json');
      checkFile(deliverable, 50, 'recon_deliverable.json');
      if (existsSync(deliverable)) {
        try {
          const data = JSON.parse(readFileSync(deliverable, 'utf-8'));
          if (!data.hosts && !data.live_hosts) missing.push('recon_deliverable.json missing hosts data');
        } catch { missing.push('recon_deliverable.json is not valid JSON'); }
      }
      break;
    }
    case 'sqli':
      checkFile(join(logDir, 'sqli_evidence.md'), 100, 'sqli_evidence.md');
      break;
    case 'cmdi':
      checkFile(join(logDir, 'cmdi_evidence.md'), 100, 'cmdi_evidence.md');
      break;
    case 'auth-attack':
      checkFile(join(logDir, 'auth_attack_evidence.md'), 50, 'auth_attack_evidence.md');
      break;
    case 'kerberoast':
      checkFile(join(memDir, 'kerberoast.md'), 50, 'kerberoast memory file');
      break;
    case 'bruteforce':
      checkFile(join(memDir, 'bruteforce.md'), 50, 'bruteforce memory file');
      break;
    case 'lateral':
      checkFile(join(logDir, 'lateral_evidence.md'), 100, 'lateral_evidence.md');
      checkFile(join(memDir, 'lateral.md'), 50, 'lateral memory file');
      break;
    case 'privesc':
      checkFile(join(logDir, 'privesc_evidence.md'), 100, 'privesc_evidence.md');
      checkFile(join(memDir, 'privesc.md'), 50, 'privesc memory file');
      break;
    case 'report':
      checkFile(join(logDir, 'pentest_report.md'), 500, 'pentest_report.md');
      break;
  }

  return { valid: missing.length === 0, missing };
}

// v2 (Bugs 1/13): Force-record phase completion to session memory from the runner
function recordPhaseCompletion(
  logDir: string,
  _agents: AgentName[],
  results: Array<{ name: AgentName; success: boolean }>
): void {
  const memPath = join(logDir, 'memory', 'session.md');
  const timestamp = new Date().toISOString();
  const lines = results.map(r =>
    `- [${timestamp}] ${r.name}: ${r.success ? 'COMPLETE' : 'FAILED'}`
  ).join('\n');
  appendFileSync(memPath, `\n\n## Phase Update (runner-injected)\n${lines}\n`);
}

// v2 (Bug 10): Generate structured input for the report agent
function generateReportInput(logDir: string): void {
  const input: Record<string, unknown> = {
    generated: new Date().toISOString(),
    phases: {} as Record<string, string>,
    attacks: [] as unknown[],
    credentials: null,
    memory: {} as Record<string, string>,
  };

  // Load attacks.jsonl
  const attacksPath = join(logDir, 'attacks.jsonl');
  if (existsSync(attacksPath)) {
    input.attacks = readFileSync(attacksPath, 'utf-8').trim().split('\n')
      .filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  }

  // Load cracked_creds.json
  const credsPath = join(logDir, 'cracked_creds.json');
  if (existsSync(credsPath)) {
    try { input.credentials = JSON.parse(readFileSync(credsPath, 'utf-8')); } catch { /* skip */ }
  }

  // Load each evidence file
  const evidenceFiles = [
    'recon_deliverable.json', 'sqli_evidence.md', 'cmdi_evidence.md',
    'auth_attack_evidence.md', 'lateral_evidence.md', 'privesc_evidence.md',
  ];
  for (const file of evidenceFiles) {
    const path = join(logDir, file);
    if (existsSync(path)) {
      (input.phases as Record<string, string>)[file] = readFileSync(path, 'utf-8').substring(0, 5000);
    }
  }

  // Load all memory files
  const memDir = join(logDir, 'memory');
  if (existsSync(memDir)) {
    for (const f of readdirSync(memDir).filter(f => f.endsWith('.md'))) {
      (input.memory as Record<string, string>)[f] = readFileSync(join(memDir, f), 'utf-8').substring(0, 3000);
    }
  }

  // v2.1 F9: Load previous run for diff -- rename existing report_input.json to .prev.json first
  const prevReportPath = join(logDir, 'report_input.prev.json');
  const currentReportPath = join(logDir, 'report_input.json');
  if (existsSync(currentReportPath)) {
    renameSync(currentReportPath, prevReportPath);
  }

  // Include previous run data if available
  if (existsSync(prevReportPath)) {
    try {
      const prev = JSON.parse(readFileSync(prevReportPath, 'utf-8'));
      input.previous_run = prev;
      input.run_diff_available = true;
    } catch { /* skip */ }
  }

  writeFileSync(currentReportPath, JSON.stringify(input, null, 2));
  console.log(`  [runner] Generated report_input.json`);
}

export async function runAgent(
  agentName: AgentName,
  configPath: string,
  retryContext?: string
): Promise<{ success: boolean; result: string | null }> {
  const config = yaml.load(readFileSync(configPath, 'utf-8')) as WraithConfig;
  const agentDef = AGENTS[agentName];
  if (!agentDef) throw new Error(`Unknown agent: ${agentName}`);
  const logDir = config.output.log_dir;

  const firstWebHost = config.target.hosts.find(h => h.web_url);
  const prompt = await loadPrompt(agentDef.promptTemplate, {
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
  });

  const mcpServers = {
    'wraith-tools': {
      command: 'node',
      args: [MCP_SERVER_PATH],
      env: { WRAITH_LOG_DIR: logDir },
    },
  };

  // Inject session memory + retry context (NO identity boundary markers)
  const memory = loadMemoryContext(logDir);
  const retryPrefix = retryContext
    ? `**RETRY NOTICE:** ${retryContext}\n\n`
    : '';
  const fullPrompt = [retryPrefix, memory, prompt].filter(Boolean).join('\n');

  const turnBudget = TURN_BUDGETS[agentName];
  console.log(`[${agentName}] Starting (budget: ${turnBudget} turns)...`);

  // v2.1 F4: Wall-clock timeout enforcement
  const wallClockSec = config.attack?.timeouts?.[agentName]
    ?? agentDef.timeout_sec
    ?? DEFAULT_TIMEOUTS[agentName]
    ?? 900;

  const timeoutPromise = new Promise<ExecutorResult>((resolve) =>
    setTimeout(() => resolve({
      result: `TIMEOUT: Agent ${agentName} exceeded ${wallClockSec}s wall-clock limit`,
      success: false,
      duration: wallClockSec * 1000,
    }), wallClockSec * 1000)
  );

  const result = await Promise.race([
    claudeRun(fullPrompt, agentName, agentDef.modelTier ?? 'medium', mcpServers, turnBudget),
    timeoutPromise,
  ]);

  if (result.result?.startsWith('TIMEOUT:')) {
    console.log(`  [timeout] ${agentName} killed after ${wallClockSec}s`);
    appendFileSync(`${logDir}/memory/session.md`, `\n- [TIMEOUT] ${agentName} exceeded ${wallClockSec}s -- partial results may exist\n`);
  }

  console.log(`[${agentName}] ${result.success ? 'Complete' : 'Failed'} (${result.duration}ms, ${result.turns ?? 0} turns)`);

  return { success: result.success, result: result.result };
}

// v2: Run a single agent with validation and optional retry
async function runAgentWithValidation(
  agentName: AgentName,
  configPath: string,
  logDir: string
): Promise<{ name: AgentName; success: boolean }> {
  const result = await runAgent(agentName, configPath);

  // B9: result === null + success === false means 0 turns (rate limit), not a timeout
  // Timeout sets result to 'TIMEOUT: ...' string; 0-turns sets result to null
  if (!result.success && result.result === null) {
    console.log(`  [retry] ${agentName} completed 0 turns (rate limit suspected) -- waiting 30s before retry`);
    await new Promise(r => setTimeout(r, 30_000));
    const retryResult = await runAgent(agentName, configPath, 'RATE_LIMIT_RETRY: Previous run completed 0 turns due to rate limiting. Please proceed with your task normally.');
    if (!retryResult.success) {
      console.log(`  [retry] ${agentName} retry also failed -- continuing`);
      return { name: agentName, success: false };
    }
    return { name: agentName, success: retryResult.success };
  }

  if (result.success) {
    const validation = validatePhaseOutput(agentName, logDir);
    if (!validation.valid) {
      console.log(`  [validation] ${agentName} reported success but missing output: ${validation.missing.join(', ')}`);
      // Retry once with explicit context about what's missing
      const retryCtx = `Your previous run reported success but did NOT produce the expected output: ${validation.missing.join('; ')}. You MUST actually execute the commands and produce these files. Do not skip or summarize.`;
      const retryResult = await runAgent(agentName, configPath, retryCtx);
      if (retryResult.success) {
        const recheck = validatePhaseOutput(agentName, logDir);
        if (!recheck.valid) {
          console.log(`  [validation] ${agentName} retry also failed: ${recheck.missing.join(', ')} -- continuing anyway`);
        }
      }
      return { name: agentName, success: retryResult.success };
    }
  }

  return { name: agentName, success: result.success };
}

export async function runWorkflow(configPath: string): Promise<void> {
  const config = yaml.load(readFileSync(configPath, 'utf-8')) as WraithConfig;
  const logDir = config.output.log_dir;
  mkdirSync(logDir, { recursive: true });
  mkdirSync(`${logDir}/memory`, { recursive: true });

  // v2: Install signal handlers for clean child process cleanup
  processManager.installSignalHandlers();

  // v2: Start pot-file watcher for background cracking detection
  const potWatcher = new PotWatcher(logDir);
  potWatcher.start();

  // v2.1: Initialize credential store and attack graph
  const credStore = new CredentialStore(logDir);
  const attackGraph = new AttackGraphService(logDir);

  // Set engagement type on attack graph
  attackGraph.setEngagement(
    config.engagement?.type ?? 'internal',
    config.engagement?.wan_ip
  );

  // Seed credential store with config credentials (if provided)
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

  // Seed attack graph with known hosts
  for (const host of config.target.hosts) {
    attackGraph.initNode(host.ip, host.name);
  }

  // B5/B6: Per-run Responder instance with correct logDir + configurable interface
  const networkInterface = config.engagement?.network_interface ?? 'eth0';
  const responderManager = new ResponderManager(logDir);
  if (config.engagement?.type !== 'external') {
    responderManager.start(networkInterface);
  }

  // Seed session.md -- shared context all agents can read
  // P1: Include agent turn budgets so agents can self-manage their time
  writeFileSync(`${logDir}/memory/session.md`, [
    `# Wraith Session`,
    `Started: ${new Date().toISOString()}`,
    ``,
    `## Target`,
    `- Domain: ${config.target.domain}`,
    `- DC: ${config.target.dc}`,
    `- Hosts: ${config.target.hosts.map(h => `${h.ip} (${h.name})`).join(', ')}`,
    ``,
    `## Status`,
    `- Phase: starting`,
    `- SOAR blocks: none yet`,
    `- Cracked credentials: none yet`,
    ``,
    `## Agent Turn Budgets`,
    `Each agent has a fixed turn budget. When you have 20 turns remaining, write your evidence and stop.`,
    `- osint-recon: 60 turns / 600s wall-clock`,
    `- recon: 100 turns / 900s`,
    `- sqli: 80 turns / 600s`,
    `- cmdi: 80 turns / 600s`,
    `- auth-attack: 80 turns / 600s`,
    `- kerberoast: 120 turns / 600s`,
    `- bruteforce: 100 turns / 900s`,
    `- lateral: 150 turns / 1200s`,
    `- privesc: 200 turns / 1200s`,
    `- report: 100 turns / 600s`,
    ``,
    `## Instructions for all agents`,
    `Call memory_read() at the start of your run to load full session context.`,
    `Call memory_write("{agentname}", ...) to save your findings.`,
    `Call memory_append("session", ...) to update shared state (SOAR blocks, creds found, etc.).`,
  ].join('\n'));

  console.log(`\n  Target: ${config.target.domain} (${config.target.dc})`);
  console.log(`  Hosts:  ${config.target.hosts.map(h => h.ip).join(', ')}`);
  console.log(`  Logs:   ${config.output.log_dir}\n`);

  const phases = getExecutionPhases(config.engagement?.type ?? 'internal');
  for (const phase of phases) {
    if (phase.length === 1) {
      const agentName = phase[0];

      // v2 (Bug 10): Generate report_input.json before report phase
      if (agentName === 'report') {
        generateReportInput(logDir);
      }

      const result = await runAgentWithValidation(agentName, configPath, logDir);

      if (agentName === 'recon' && !result.success) {
        potWatcher.stop();
        throw new Error('Recon failed -- cannot proceed without target map');
      }

      // v2 (Bugs 1/13): Force-record phase completion
      recordPhaseCompletion(logDir, phase, [result]);
    } else {
      // B1: Stagger parallel agents 12s apart to avoid OAuth rate limit
      const results = await Promise.allSettled(
        phase.map((agentName, i) =>
          new Promise<void>(resolve => setTimeout(resolve, i * 12_000))
            .then(() => runAgentWithValidation(agentName, configPath, logDir))
        )
      );

      const phaseResults = results.map((r, i) => ({
        name: phase[i],
        success: r.status === 'fulfilled' && r.value.success,
      }));

      const failed = phaseResults.filter(r => !r.success).map(r => r.name);
      if (failed.length > 0) {
        console.log(`  [warn] These agents failed: ${failed.join(', ')} -- continuing`);
      }

      // v2 (Bugs 1/13): Force-record phase completion
      recordPhaseCompletion(logDir, phase, phaseResults);
    }
  }

  // v2: Stop pot watcher
  potWatcher.stop();

  // v2.1: Stop Responder
  responderManager.stop();

  console.log('\n  Wraith complete. Check attack-logs/ for results.');
  console.log(`  Report: ${config.output.log_dir}/pentest_report.md\n`);
}
