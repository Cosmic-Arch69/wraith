// v3.7.0: Engagement mode differentiation
// External hides internal IPs until pivot. Assumed-breach skips recon, seeds graph.

import type { AttackGraph, WraithV3Config } from '../types/index.js';
import { AttackGraphService } from '../services/attack-graph.js';

// Check if any edge goes from WAN IP to an internal IP
export function hasPivotedPastFirewall(graph: AttackGraph): boolean {
  const wanIp = graph.wan_ip;
  if (!wanIp) return false;

  // Check edges: if WAN IP connects to any non-WAN IP, pivot achieved
  for (const edge of graph.edges) {
    if (edge.from === wanIp && edge.to !== wanIp) return true;
  }

  // Also check pivot_points
  if (graph.pivot_points.length > 0) return true;

  // Check if any internal node has access_level > none (discovered via WAN)
  for (const [ip, node] of Object.entries(graph.nodes)) {
    if (ip !== wanIp && node.access_level !== 'none') return true;
  }

  return false;
}

// Get template variables appropriate for engagement mode
export function getExternalModeVars(config: WraithV3Config): Record<string, string> {
  return {
    domain: '',             // unknown in external mode -- discover via OSINT
    dc: '',                 // unknown
    hosts: JSON.stringify([{ ip: config.engagement?.wan_ip ?? '', name: 'WAN-Target' }]),
    credentials: JSON.stringify({ domain_user: '', domain_pass: '' }),
    wan_ip: config.engagement?.wan_ip ?? '',
    engagement_type: 'external',
    web_host: config.engagement?.wan_ip ?? '',
    web_url: '',
    domain_user: '',
    domain_pass: '',
    web_dvwa_user: '',
    web_dvwa_pass: '',
  };
}

export function getInternalModeVars(config: WraithV3Config): Record<string, string> {
  const firstWebHost = config.target.hosts.find(h => h.web_url);
  return {
    domain: config.target.domain,
    dc: config.target.dc,
    hosts: JSON.stringify(config.target.hosts),
    credentials: JSON.stringify(config.target.credentials),
    wan_ip: config.engagement?.wan_ip ?? '',
    engagement_type: 'internal',
    web_host: firstWebHost?.ip ?? '',
    web_url: firstWebHost?.web_url ?? '',
    domain_user: config.target.credentials.domain_user,
    domain_pass: config.target.credentials.domain_pass,
    web_dvwa_user: config.target.credentials.web_dvwa_user ?? 'admin',
    web_dvwa_pass: config.target.credentials.web_dvwa_pass ?? 'password',
  };
}

export function getAssumedBreachVars(config: WraithV3Config): Record<string, string> {
  const vars = getInternalModeVars(config);
  vars.engagement_type = 'assumed-breach';
  return vars;
}

// Build mode-aware context for agent prompts
// External: hides internal IPs until pivot detected
export function buildModeAwareContext(
  engagementType: string,
  graph: AttackGraph,
  hasPivoted: boolean,
): string {
  if (engagementType !== 'external' || hasPivoted) {
    return ''; // Internal/assumed-breach or post-pivot: no filtering needed
  }

  // External pre-pivot: only show WAN-facing information
  const wanIp = graph.wan_ip;
  const wanNode = wanIp ? graph.nodes[wanIp] : undefined;

  if (!wanNode) return '';

  const parts = [
    '## External Engagement -- Pre-Pivot',
    `You are attacking from OUTSIDE the network. You can only see the WAN interface.`,
    `- WAN Target: ${wanIp}`,
    `- Services: ${wanNode.services.join(', ') || 'unknown -- scan first'}`,
    `- Access: ${wanNode.access_level}`,
    '',
    'Internal targets will be revealed after successful pivot through the perimeter.',
  ];

  return parts.join('\n') + '\n\n---\n\n';
}

// Seed graph for assumed-breach mode
export function seedAssumedBreach(
  config: WraithV3Config,
  graphService: AttackGraphService,
): void {
  // Mark all configured hosts as accessible with user-level access
  for (const host of config.target.hosts) {
    graphService.initNode(host.ip, host.name);
    graphService.updateNode(host.ip, {
      status: 'up',
      access_level: 'user',
    });
  }
  if (config.target.dc) {
    graphService.initNode(config.target.dc, 'DC');
    graphService.updateNode(config.target.dc, {
      status: 'up',
      access_level: 'user',
    });
  }
}
