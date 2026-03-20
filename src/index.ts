#!/usr/bin/env node
// Wraith v3.0.0 CLI entry point
// Default: adaptive pipeline. --legacy: v2 static DAG.

import 'dotenv/config';
import { readFileSync, existsSync, createReadStream } from 'node:fs';
import { join } from 'node:path';
import { parseCli, printUsage } from './cli.js';
import { runPipeline } from './pipeline/runner.js';
import { runWorkflow } from './runner-legacy.js';
import { loadPrompt } from './services/prompt-manager.js';
import { AGENTS } from './session-manager.js';
import type { WraithV3Config } from './types/index.js';
import yaml from 'js-yaml';

const cli = parseCli();

async function main() {
  switch (cli.command) {

    case 'run': {
      if (!existsSync(cli.config)) {
        console.error(`Config not found: ${cli.config}`);
        process.exit(1);
      }

      const config = yaml.load(readFileSync(cli.config, 'utf-8')) as WraithV3Config;

      // Apply CLI overrides to planning config
      if (cli.maxRounds || cli.maxAgents || cli.objective) {
        config.planning = {
          max_rounds: cli.maxRounds ?? config.planning?.max_rounds ?? 10,
          max_total_agents: cli.maxAgents ?? config.planning?.max_total_agents ?? 30,
          max_concurrent_agents: config.planning?.max_concurrent_agents ?? 3,
          objective: cli.objective ?? config.planning?.objective ?? 'full_assessment',
          stealth_mode: config.planning?.stealth_mode ?? false,
        };
      }

      if (cli.dryRun) {
        console.log(`\n  Wraith v3.0.0`);
        console.log(`  Target: ${config.target.domain} (${config.target.dc})`);
        console.log(`  Mode: ${cli.legacy ? 'legacy (v2 DAG)' : 'adaptive pipeline (v3)'}`);
        console.log('\n  [dry-run] Validating prompts...');
        const firstWebHost = config.target.hosts.find(h => h.web_url);
        for (const [name, agent] of Object.entries(AGENTS)) {
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
            wan_ip: config.engagement?.wan_ip ?? '',
            engagement_type: config.engagement?.type ?? 'internal',
            agent_id: '',
            round_context: '',
          });
          const unresolved = prompt.match(/\{\{[^}]+\}\}/g);
          const status = unresolved ? `WARN (unresolved: ${unresolved.join(', ')})` : 'OK';
          console.log(`  [${name}] ${status}`);
        }
        console.log('\n  [dry-run] All prompts validated. Run without --dry-run to execute.');
        return;
      }

      if (cli.legacy) {
        console.log(`\n  Wraith v3.0.0 (legacy mode)`);
        await runWorkflow(cli.config);
      } else {
        await runPipeline(cli.config);
      }
      break;
    }

    case 'status': {
      const logFile = join('attack-logs', 'attacks.jsonl');
      if (!existsSync(logFile)) {
        console.log('No attack log found. Run a workflow first.');
        return;
      }
      const lines = readFileSync(logFile, 'utf-8').trim().split('\n').filter(Boolean);
      const events = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      const byResult = events.reduce((acc: Record<string, number>, e: Record<string, unknown>) => {
        const r = e.result as string;
        acc[r] = (acc[r] ?? 0) + 1;
        return acc;
      }, {});
      console.log(`\n  Attack log: ${lines.length} events`);
      for (const [result, count] of Object.entries(byResult)) {
        console.log(`  ${result}: ${count}`);
      }
      break;
    }

    case 'logs': {
      const logFile = join('attack-logs', 'attacks.jsonl');
      if (!existsSync(logFile)) {
        console.log('No attack log yet. Run a workflow first.');
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
