// Wraith CLI -- argument parsing
// v3: Added --legacy, --max-rounds, --max-agents, --objective flags

import { parseArgs } from 'node:util';

export type CliCommand = 'run' | 'status' | 'logs';

export interface CliArgs {
  command: CliCommand;
  config: string;
  workflowId?: string;
  follow: boolean;
  dryRun: boolean;
  engagement?: string;
  legacy: boolean;
  maxRounds?: number;
  maxAgents?: number;
  objective?: string;
  skipPreflight: boolean;  // v3.7.0: skip pre-engagement checks
}

export function parseCli(): CliArgs {
  const args = process.argv.slice(2);
  const command = (args[0] ?? 'run') as CliCommand;

  const { values } = parseArgs({
    args: args.slice(1),
    options: {
      config:      { type: 'string',  short: 'c', default: 'configs/yashnet-lab.yaml' },
      'workflow-id': { type: 'string', short: 'w' },
      follow:      { type: 'boolean', short: 'f', default: false },
      'dry-run':   { type: 'boolean', short: 'd', default: false },
      engagement:  { type: 'string',  short: 'e' },
      legacy:      { type: 'boolean', default: false },
      'max-rounds': { type: 'string' },
      'max-agents': { type: 'string' },
      objective:   { type: 'string',  short: 'o' },
      'skip-preflight': { type: 'boolean', default: false },
    },
    strict: false,
  });

  return {
    command,
    config: values.config as string,
    workflowId: values['workflow-id'] as string | undefined,
    follow: values.follow as boolean,
    dryRun: values['dry-run'] as boolean,
    engagement: values.engagement as string | undefined,
    legacy: values.legacy as boolean,
    maxRounds: values['max-rounds'] ? parseInt(values['max-rounds'] as string, 10) : undefined,
    maxAgents: values['max-agents'] ? parseInt(values['max-agents'] as string, 10) : undefined,
    objective: values.objective as string | undefined,
    skipPreflight: values['skip-preflight'] as boolean,
  };
}

export function printUsage() {
  console.log(`
  Wraith v3.7.0 -- Autonomous AI Pentesting Framework

  Usage:
    wraith run   [--config <path>] [--dry-run]   Start adaptive pipeline
    wraith run   --legacy [--config <path>]       Run v2 static DAG mode
    wraith status --workflow-id <id>             Check workflow status
    wraith logs  [--follow]                      Tail attack log

  Options:
    -c, --config       Config file path (default: configs/yashnet-lab.yaml)
    -d, --dry-run      Validate config + prompts without executing
    -e, --engagement   Override engagement type (external, internal, assumed-breach)
    -o, --objective    Set objective (full_assessment, domain_admin, web_only, cred_harvest)
    --legacy           Use v2 static DAG runner instead of adaptive pipeline
    --max-rounds       Override max attack rounds (default: 10)
    --max-agents       Override max total agents (default: 30)
    -f, --follow       Follow log output (for logs command)
    -w, --workflow-id  Workflow ID (for status command, legacy)
  `);
}
