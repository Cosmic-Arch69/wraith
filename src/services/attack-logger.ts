// Structured attack event logger
// Writes JSONL to attack-logs/attacks.jsonl for correlation with Wazuh

import { appendFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { AttackEvent } from '../types/index.js';

export class AttackLogger {
  private logPath: string;

  constructor(logDir: string) {
    if (!existsSync(logDir)) mkdirSync(logDir, { recursive: true });
    this.logPath = join(logDir, 'attacks.jsonl');
  }

  log(event: Omit<AttackEvent, 'timestamp'>): void {
    const full: AttackEvent = {
      timestamp: new Date().toISOString(),
      ...event,
    };
    appendFileSync(this.logPath, JSON.stringify(full) + '\n');
    console.log(`[${full.technique}] ${full.result} -- ${full.details}`);
  }
}
