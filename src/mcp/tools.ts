// Wraith MCP tool definitions and handlers
// Provides pentest tools to Claude agents via MCP protocol

import { execSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, appendFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { AttackEvent } from '../types/index.js';

export const PENTEST_TOOLS = [
  {
    name: 'execute_command',
    description: 'Execute a shell command (Impacket, CrackMapExec, nmap, etc). Returns stdout+stderr.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        command: { type: 'string', description: 'The shell command to run' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 60)' },
      },
      required: ['command'],
    },
  },
  {
    name: 'log_attack',
    description: 'Log an attack event to the structured JSON attack log',
    inputSchema: {
      type: 'object' as const,
      properties: {
        phase: { type: 'string' },
        technique: { type: 'string', description: 'MITRE ATT&CK technique ID (e.g. T1558.003)' },
        techniqueName: { type: 'string' },
        targetIp: { type: 'string' },
        targetUser: { type: 'string' },
        targetService: { type: 'string' },
        targetUrl: { type: 'string' },
        tool: { type: 'string' },
        result: { type: 'string', enum: ['success', 'failed', 'blocked', 'skipped'] },
        wazuhRuleExpected: { type: 'string' },
        details: { type: 'string' },
      },
      required: ['phase', 'technique', 'techniqueName', 'tool', 'result', 'wazuhRuleExpected', 'details'],
    },
  },
  {
    name: 'read_file',
    description: 'Read a file from the filesystem',
    inputSchema: {
      type: 'object' as const,
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  },
  {
    name: 'write_file',
    description: 'Write content to a file',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string' },
        content: { type: 'string' },
      },
      required: ['path', 'content'],
    },
  },
  {
    name: 'check_connectivity',
    description: 'Check if a target IP/host is reachable (detect if SOAR blocked us)',
    inputSchema: {
      type: 'object' as const,
      properties: {
        host: { type: 'string' },
        port: { type: 'number' },
      },
      required: ['host'],
    },
  },
];

const LOG_DIR = process.env.WRAITH_LOG_DIR ?? './attack-logs';
const ATTACK_LOG = join(LOG_DIR, 'attacks.jsonl');
const SOURCE_IP_FILE = join(LOG_DIR, 'source_ip.txt');

function getSourceIp(): string {
  if (existsSync(SOURCE_IP_FILE)) {
    return readFileSync(SOURCE_IP_FILE, 'utf-8').trim();
  }
  try {
    const result = spawnSync('curl', ['-s', 'https://api.ipify.org'], { timeout: 5000 });
    const ip = result.stdout?.toString().trim() ?? 'unknown';
    writeFileSync(SOURCE_IP_FILE, ip);
    return ip;
  } catch {
    return 'unknown';
  }
}

export function handleTool(name: string, input: Record<string, unknown>): string {
  switch (name) {

    case 'execute_command': {
      const cmd = input.command as string;
      const timeout = ((input.timeout_sec as number) ?? 60) * 1000;
      try {
        const output = execSync(cmd, {
          timeout,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        return output || '(no output)';
      } catch (err: unknown) {
        const e = err as { stdout?: string; stderr?: string; message?: string };
        return `ERROR:\n${e.stdout ?? ''}\n${e.stderr ?? ''}\n${e.message ?? ''}`;
      }
    }

    case 'log_attack': {
      const event: AttackEvent = {
        timestamp: new Date().toISOString(),
        phase: input.phase as string,
        technique: input.technique as string,
        techniqueName: input.techniqueName as string,
        target: {
          ip: (input.targetIp as string) ?? '',
          user: input.targetUser as string | undefined,
          service: input.targetService as string | undefined,
          url: input.targetUrl as string | undefined,
        },
        sourceIp: getSourceIp(),
        tool: input.tool as string,
        result: input.result as AttackEvent['result'],
        wazuhRuleExpected: input.wazuhRuleExpected as string,
        details: input.details as string,
      };
      appendFileSync(ATTACK_LOG, JSON.stringify(event) + '\n');
      return `Logged: ${event.technique} -> ${event.result}`;
    }

    case 'read_file': {
      try {
        return readFileSync(input.path as string, 'utf-8');
      } catch (err) {
        return `Error reading file: ${err}`;
      }
    }

    case 'write_file': {
      try {
        writeFileSync(input.path as string, input.content as string, 'utf-8');
        return `Written: ${input.path}`;
      } catch (err) {
        return `Error writing file: ${err}`;
      }
    }

    case 'check_connectivity': {
      const host = input.host as string;
      const port = input.port as number | undefined;
      try {
        const cmd = port
          ? `nc -zw3 ${host} ${port} 2>&1 && echo REACHABLE || echo BLOCKED`
          : `ping -c 1 -W 3 ${host} 2>&1 | tail -1`;
        const result = execSync(cmd, { timeout: 10000, encoding: 'utf-8' });
        return result.trim();
      } catch {
        return 'BLOCKED (command failed)';
      }
    }

    default:
      return `Unknown tool: ${name}`;
  }
}
