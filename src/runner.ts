// Wraith direct runner -- no Temporal required
// Executes the agent DAG in-process: sequential phases + parallel where safe

import { readFileSync, mkdirSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import yaml from 'js-yaml';
import { runAgent as claudeRun } from './ai/claude-executor.js';
import type { AgentName, WraithConfig } from './types/index.js';
import { AGENTS, EXECUTION_PHASES } from './session-manager.js';
import { loadPrompt } from './services/prompt-manager.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const MCP_SERVER_PATH = join(__dirname, 'mcp', 'server.js');

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

export async function runAgent(
  agentName: AgentName,
  configPath: string
): Promise<{ success: boolean; result: string | null }> {
  const config = yaml.load(readFileSync(configPath, 'utf-8')) as WraithConfig;
  const agentDef = AGENTS[agentName];
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
  });

  const mcpServers = {
    'wraith-tools': {
      command: 'node',
      args: [MCP_SERVER_PATH],
      env: { WRAITH_LOG_DIR: logDir },
    },
  };

  // Inject session memory at the top of every prompt -- survives context compression
  const memory = loadMemoryContext(logDir);
  const fullPrompt = memory ? `${memory}${prompt}` : prompt;

  console.log(`[${agentName}] Starting...`);
  const result = await claudeRun(fullPrompt, agentName, agentDef.modelTier ?? 'medium', mcpServers);
  console.log(`[${agentName}] ${result.success ? 'Complete' : 'Failed'} (${result.duration}ms, ${result.turns ?? 0} turns)`);

  return { success: result.success, result: result.result };
}

export async function runWorkflow(configPath: string): Promise<void> {
  const config = yaml.load(readFileSync(configPath, 'utf-8')) as WraithConfig;
  const logDir = config.output.log_dir;
  mkdirSync(logDir, { recursive: true });
  mkdirSync(`${logDir}/memory`, { recursive: true });

  // Seed session.md -- shared context all agents can read
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
    `## Instructions for all agents`,
    `Call memory_read() at the start of your run to load full session context.`,
    `Call memory_write("{agentname}", ...) to save your findings.`,
    `Call memory_append("session", ...) to update shared state (SOAR blocks, creds found, etc.).`,
  ].join('\n'));

  console.log(`\n  Target: ${config.target.domain} (${config.target.dc})`);
  console.log(`  Hosts:  ${config.target.hosts.map(h => h.ip).join(', ')}`);
  console.log(`  Logs:   ${config.output.log_dir}\n`);

  for (const phase of EXECUTION_PHASES) {
    if (phase.length === 1) {
      const result = await runAgent(phase[0], configPath);
      if (phase[0] === 'recon' && !result.success) {
        throw new Error('Recon failed -- cannot proceed without target map');
      }
    } else {
      // Parallel phase -- run all agents concurrently, collect results
      const results = await Promise.allSettled(
        phase.map(agentName => runAgent(agentName, configPath))
      );
      const failed = results
        .map((r, i) => ({ name: phase[i], r }))
        .filter(({ r }) => r.status === 'rejected' || (r.status === 'fulfilled' && !r.value.success))
        .map(({ name }) => name);
      if (failed.length > 0) {
        console.log(`  [warn] These agents failed: ${failed.join(', ')} -- continuing`);
      }
    }
  }

  console.log('\n  Wraith complete. Check attack-logs/ for results.');
  console.log(`  Report: ${config.output.log_dir}/pentest_report.md\n`);
}
