// Watches hashcat/john pot files for newly cracked credentials
// Logs each new crack as an AttackEvent and appends to session memory

import { readFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, basename } from 'node:path';
import type { AttackEvent } from '../types/index.js';

const POT_FILES: ReadonlyArray<{ path: string; tool: string }> = [
  { path: '/tmp/asrep.pot', tool: 'john' },
  { path: '/tmp/kerberoast.pot', tool: 'john' },
  { path: '/tmp/ntlm.pot', tool: 'john' },
  { path: '/tmp/john.pot', tool: 'john' },
  { path: '/tmp/hashcat.potfile', tool: 'hashcat' },
  { path: '/usr/share/responder/logs/Responder-Session.log', tool: 'responder' },
];

// NTLMv2 format: username::DOMAIN:challenge:NTHash:NTHashResponse
const NTLMV2_HASH_RE = /^([^:]+)::([^:]+):[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+$/;

/**
 * If the given line matches the Responder NTLMv2 hash format, returns the
 * extracted username. Returns null if the line is not a captured hash.
 */
export function extractResponderUsername(line: string): string | null {
  const match = NTLMV2_HASH_RE.exec(line.trim());
  return match?.[1] ?? null;
}

export class PotWatcher {
  private logDir: string;
  private seen: Set<string> = new Set();
  private interval: ReturnType<typeof setInterval> | null = null;

  constructor(logDir: string) {
    this.logDir = logDir;
  }

  start(): void {
    // Seed with existing lines so we only capture new cracks
    this.seedExisting();
    this.interval = setInterval(() => this.check(), 10_000);
  }

  stop(): void {
    if (this.interval !== null) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }

  private seedExisting(): void {
    for (const pot of POT_FILES) {
      if (!existsSync(pot.path)) continue;
      const lines = readFileSync(pot.path, 'utf-8').split('\n');
      for (const line of lines) {
        if (line.trim()) this.seen.add(line.trim());
      }
    }
  }

  private check(): void {
    for (const pot of POT_FILES) {
      if (!existsSync(pot.path)) continue;

      const lines = readFileSync(pot.path, 'utf-8').split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || this.seen.has(trimmed)) continue;

        this.seen.add(trimmed);
        this.onNewCrack(trimmed, pot.tool, pot.path);
      }
    }
  }

  private onNewCrack(line: string, tool: string, potPath: string): void {
    const timestamp = new Date().toISOString();
    const potName = basename(potPath);

    console.log(`[pot-watcher] New crack from ${potName}: ${line}`);

    // Write attack event
    const attacksPath = join(this.logDir, 'attacks.jsonl');
    const event: AttackEvent = {
      timestamp,
      phase: 'credential-crack',
      technique: 'T1110.002',
      techniqueName: 'Password Cracking',
      target: { ip: 'N/A' },
      sourceIp: 'localhost',
      tool,
      result: 'success',
      wazuhRuleExpected: '',
      details: `Cracked from ${potName}: ${line}`,
    };
    appendFileSync(attacksPath, JSON.stringify(event) + '\n');

    // Append to session memory
    const memoryDir = join(this.logDir, 'memory');
    if (!existsSync(memoryDir)) mkdirSync(memoryDir, { recursive: true });
    const sessionPath = join(memoryDir, 'session.md');
    appendFileSync(
      sessionPath,
      `- **${timestamp}** -- Cracked (${tool}, ${potName}): \`${line}\`\n`,
    );
  }
}
