// Temporal activities -- thin wrappers around Claude agent execution

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import yaml from 'js-yaml';
import { runAgent as claudeRun } from '../ai/claude-executor.js';
import type { AgentName, WraithConfig } from '../types/index.js';
import { AGENTS } from '../session-manager.js';
import { loadPrompt } from '../services/prompt-manager.js';

// Resolve absolute path to the MCP server binary (compiled at dist/mcp/server.js)
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const MCP_SERVER_PATH = join(__dirname, '..', 'mcp', 'server.js');

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

  // Wire MCP server so agents can call execute_command, log_attack, etc.
  const mcpServers = {
    'wraith-tools': {
      command: 'node',
      args: [MCP_SERVER_PATH],
      env: { WRAITH_LOG_DIR: logDir },
    },
  };

  console.log(`[${agentName}] Starting...`);
  const result = await claudeRun(prompt, agentName, agentDef.modelTier ?? 'medium', mcpServers);
  console.log(`[${agentName}] ${result.success ? 'Complete' : 'Failed'} (${result.duration}ms, ${result.turns} turns)`);

  return { success: result.success, result: result.result };
}
