// Wraith CLI -- argument parsing

import { parseArgs } from 'node:util';

export type CliCommand = 'run' | 'status' | 'logs';

export interface CliArgs {
  command: CliCommand;
  config: string;
  workflowId?: string;
  follow: boolean;
  dryRun: boolean;
  engagement?: string;
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
  };
}

export function printUsage() {
  console.log(`
  Wraith -- Autonomous AI Pentesting Framework

  Usage:
    wraith run   [--config <path>] [--dry-run]   Start a pentest workflow
    wraith status --workflow-id <id>             Check workflow status
    wraith logs  [--follow]                      Tail attack log

  Options:
    -c, --config       Config file path (default: configs/yashnet-lab.yaml)
    -w, --workflow-id  Temporal workflow ID (for status command)
    -f, --follow       Follow log output (for logs command)
    -d, --dry-run      Validate config + prompts without executing
    -e, --engagement   Override engagement type (external, internal, assumed-breach)
  `);
}
