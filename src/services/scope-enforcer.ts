// v3.7.0: Scope enforcer -- validates target IPs before attack execution
// Critical safety feature: prevents out-of-scope attacks

import type { WraithV3Config } from '../types/index.js';
import { getAuthorizedTargets } from './authorization.js';

export class ScopeViolationError extends Error {
  constructor(
    public readonly targetIp: string,
    public readonly toolName: string,
    public readonly agentId: string,
  ) {
    super(`SCOPE VIOLATION: ${toolName} targeted ${targetIp} (agent: ${agentId}) -- not in authorized scope`);
    this.name = 'ScopeViolationError';
  }
}

export class ScopeEnforcer {
  private readonly authorizedTargets: Set<string>;

  constructor(config: WraithV3Config) {
    this.authorizedTargets = new Set(getAuthorizedTargets(config));
  }

  // Build from env var (for MCP server process)
  static fromEnv(): ScopeEnforcer | null {
    const targets = process.env.WRAITH_AUTHORIZED_TARGETS;
    if (!targets) return null;

    const enforcer = new ScopeEnforcer({ target: { domain: '', dc: '', hosts: [], credentials: { domain_user: '', domain_pass: '' } }, attack: { randomize: false, delay_min_sec: 0, delay_max_sec: 0, phases: [] }, output: { log_dir: '', report: false } });
    for (const ip of targets.split(',').map(s => s.trim()).filter(Boolean)) {
      enforcer.authorizedTargets.add(ip);
    }
    return enforcer;
  }

  isInScope(targetIp: string): boolean {
    if (!targetIp) return true; // No target = no scope check needed
    // Normalize: strip port if present
    const ip = targetIp.split(':')[0].trim();
    if (!ip) return true;
    // Allow localhost / loopback
    if (ip === '127.0.0.1' || ip === 'localhost' || ip === '0.0.0.0') return true;
    return this.authorizedTargets.has(ip);
  }

  enforce(targetIp: string, toolName: string, agentId: string = 'unknown'): void {
    if (!this.isInScope(targetIp)) {
      throw new ScopeViolationError(targetIp, toolName, agentId);
    }
  }

  getAuthorizedList(): string[] {
    return Array.from(this.authorizedTargets);
  }
}

// Extract IP-like patterns from a command string (best-effort for execute_command)
export function extractIpsFromCommand(command: string): string[] {
  const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const matches: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = ipPattern.exec(command)) !== null) {
    matches.push(match[1]);
  }
  return matches;
}
