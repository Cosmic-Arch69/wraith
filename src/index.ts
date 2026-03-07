#!/usr/bin/env node
// Wraith CLI entry point

import 'dotenv/config';
import { readFileSync, existsSync } from 'node:fs';
import { createReadStream } from 'node:fs';
import { join } from 'node:path';
import { parseCli, printUsage } from './cli.js';
import { connectTemporal, startWraithWorkflow, getWorkflowStatus } from './temporal/client.js';
import { loadPrompt } from './services/prompt-manager.js';
import { AGENTS } from './session-manager.js';
import type { WraithConfig } from './types/index.js';
import yaml from 'js-yaml';

const cli = parseCli();

async function main() {
  switch (cli.command) {

    case 'run': {
      if (!existsSync(cli.config)) {
        console.error(`Config not found: ${cli.config}`);
        process.exit(1);
      }

      const config = yaml.load(readFileSync(cli.config, 'utf-8')) as WraithConfig;
      console.log(`\n  Wraith v0.1.0`);
      console.log(`  Target: ${config.target.domain} (${config.target.dc})`);
      console.log(`  Hosts:  ${config.target.hosts.map(h => h.ip).join(', ')}`);
      console.log(`  Config: ${cli.config}`);

      if (cli.dryRun) {
        console.log('\n  [dry-run] Validating prompts...');
        for (const [name, agent] of Object.entries(AGENTS)) {
          const firstWebHost = config.target.hosts.find(h => h.web_url);
          const prompt = await loadPrompt(agent.promptTemplate, {
            domain: config.target.domain,
            dc: config.target.dc,
            hosts: JSON.stringify(config.target.hosts),
            credentials: JSON.stringify(config.target.credentials),
            logDir: config.output.log_dir,
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
          const unresolved = prompt.match(/\{\{[^}]+\}\}/g);
          const status = unresolved ? `WARN (unresolved: ${unresolved.join(', ')})` : 'OK';
          console.log(`  [${name}] ${status}`);
        }
        console.log('\n  [dry-run] All prompts validated. Run without --dry-run to execute.');
        return;
      }

      console.log('\n  Connecting to Temporal...');
      const { client } = await connectTemporal();
      const workflowId = await startWraithWorkflow(client, cli.config);
      console.log(`  Workflow started: ${workflowId}`);
      console.log(`  Temporal UI:     http://localhost:8233`);
      console.log(`  Status:          wraith status --workflow-id ${workflowId}`);
      console.log(`  Logs:            wraith logs --follow`);
      console.log(`  Attack log:      ${config.output.log_dir}/attacks.jsonl\n`);
      break;
    }

    case 'status': {
      if (!cli.workflowId) {
        console.error('--workflow-id required for status command');
        process.exit(1);
      }
      const { client } = await connectTemporal();
      const status = await getWorkflowStatus(client, cli.workflowId);
      console.log(JSON.stringify(status, null, 2));
      break;
    }

    case 'logs': {
      const logFile = join('attack-logs', 'attacks.jsonl');
      if (!existsSync(logFile)) {
        console.log('No attack log yet. Start a workflow first.');
        return;
      }
      const content = readFileSync(logFile, 'utf-8').trim();
      if (!content) {
        console.log('Attack log is empty.');
        return;
      }
      for (const line of content.split('\n')) {
        if (!line) continue;
        try {
          const event = JSON.parse(line);
          const result = event.result === 'success' ? '[+]' : event.result === 'blocked' ? '[!]' : '[-]';
          console.log(`${result} ${event.timestamp} | ${event.technique} | ${event.target.ip} | ${event.tool}`);
        } catch {
          console.log(line);
        }
      }
      if (cli.follow) {
        console.log('Following... (Ctrl+C to stop)');
        // Simple tail -f equivalent using readline
        const stream = createReadStream(logFile, { start: readFileSync(logFile).length });
        stream.on('data', (chunk) => {
          const lines = chunk.toString().split('\n').filter(Boolean);
          for (const line of lines) {
            try {
              const event = JSON.parse(line);
              const result = event.result === 'success' ? '[+]' : event.result === 'blocked' ? '[!]' : '[-]';
              console.log(`${result} ${event.timestamp} | ${event.technique} | ${event.target.ip} | ${event.tool}`);
            } catch {
              console.log(line);
            }
          }
        });
      }
      break;
    }

    default:
      printUsage();
  }
}

main().catch((err) => {
  console.error('Error:', err.message ?? err);
  process.exit(1);
});
