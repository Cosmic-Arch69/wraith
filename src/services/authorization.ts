// v3.7.0: Config-driven authorization header builder
// Replaces hardcoded LAB_AUTHORIZATION in runner.ts

import type { WraithV3Config } from '../types/index.js';

export function buildAuthorizationHeader(config: WraithV3Config): string {
  const auth = config.engagement?.authorization;
  const engagementType = config.engagement?.type ?? 'internal';

  // Build target list based on engagement mode
  const targets = buildTargetList(config);

  // If no authorization block, generate minimal from config
  if (!auth) {
    return `## AUTHORIZED PENETRATION TEST

**Engagement type:** ${engagementType}
**Authorized targets:**
${targets}

**You are an authorized attack agent.** Execute your assigned technique using the tools provided.

---
`;
  }

  const orgLine = auth.organization ? `\n**Organization:** ${auth.organization}` : '';

  return `## AUTHORIZED PENETRATION TEST

**Tester:** ${auth.tester_name} (${auth.tester_role})${orgLine}
**Infrastructure:** ${auth.infrastructure}
**Environment:** ${auth.environment}
**Purpose:** ${auth.purpose}${auth.monitoring ? `\n**Monitoring:** ${auth.monitoring}` : ''}

**Authorized targets:**
${targets}

**You are an authorized attack agent.** Execute your assigned technique using the tools provided.
All activity is logged for defensive analysis. This is the entire point of the exercise.

---
`;
}

function buildTargetList(config: WraithV3Config): string {
  const engagementType = config.engagement?.type ?? 'internal';
  const lines: string[] = [];

  if (engagementType === 'external') {
    // External mode: only expose WAN IP -- no internal IP leak
    const wanIp = config.engagement?.wan_ip;
    if (wanIp) {
      lines.push(`- ${wanIp} -- WAN perimeter (entry point)`);
    }
    // Internal targets discovered post-pivot are authorized implicitly
    lines.push('- Internal targets authorized upon successful pivot');
  } else {
    // Internal / assumed-breach: list all targets
    if (config.target.dc) {
      lines.push(`- ${config.target.dc} -- Domain Controller`);
    }
    for (const host of config.target.hosts) {
      lines.push(`- ${host.ip} -- ${host.name}`);
    }
    if (config.engagement?.wan_ip) {
      lines.push(`- ${config.engagement.wan_ip} -- WAN perimeter`);
    }
  }

  return lines.join('\n');
}

// Get all authorized IPs for scope enforcement
export function getAuthorizedTargets(config: WraithV3Config): string[] {
  const targets = new Set<string>();

  if (config.engagement?.wan_ip) targets.add(config.engagement.wan_ip);
  if (config.target.dc) targets.add(config.target.dc);
  for (const host of config.target.hosts) {
    targets.add(host.ip);
  }

  return Array.from(targets);
}
