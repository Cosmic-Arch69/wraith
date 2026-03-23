// Live attack graph tracking discovered hosts, blocked paths, and open vectors
// v2.1 Features: F3 (Attack Graph), F8 (SOAR Detection), F10 (DVWA tracking)

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ACCESS_LEVEL_RANK } from '../types/index.js';
import type { AttackGraph, AttackGraphNode, EngagementType } from '../types/index.js';

const RESPONSE_TIME_WINDOW = 5;
const BLOCK_DETECTION_WINDOW = 3;
const BLOCK_THRESHOLD_MS = 5000;

export class AttackGraphService {
  private graph: AttackGraph;
  private graphPath: string;

  constructor(logDir: string) {
    if (!existsSync(logDir)) mkdirSync(logDir, { recursive: true });
    this.graphPath = join(logDir, 'attack-graph.json');

    if (existsSync(this.graphPath)) {
      const raw = readFileSync(this.graphPath, 'utf-8');
      this.graph = JSON.parse(raw) as AttackGraph;
    } else {
      this.graph = {
        engagement_type: 'internal',
        nodes: {},
        edges: [],
        pivot_points: [],
        soar_blocked_ips: [],
        timeline: [],
      };
    }
  }

  setEngagement(type: EngagementType, wan_ip?: string): void {
    this.graph.engagement_type = type;
    if (wan_ip !== undefined) {
      this.graph.wan_ip = wan_ip;
    }
    this.persist();
  }

  initNode(ip: string, host: string): void {
    if (this.graph.nodes[ip]) return;
    this.graph.nodes[ip] = {
      host,
      ip,
      status: 'unknown',
      services: [],
      access_level: 'none',
      vectors_open: [],
      vectors_blocked: [],
      response_times: [],
      last_seen: new Date().toISOString(),
      notes: [],
    };
    this.persist();
  }

  updateNode(ip: string, updates: Partial<AttackGraphNode>): void {
    const existing = this.graph.nodes[ip];
    if (!existing) return;

    // Merge scalar fields
    if (updates.host !== undefined) existing.host = updates.host;
    if (updates.status !== undefined) existing.status = updates.status;
    // v3.6.0 BUG-NEW-4/7: Monotonic access level guard -- never downgrade
    if (updates.access_level !== undefined) {
      const currentRank = ACCESS_LEVEL_RANK[existing.access_level] ?? 0;
      const proposedRank = ACCESS_LEVEL_RANK[updates.access_level] ?? 0;
      if (proposedRank > currentRank) {
        existing.access_level = updates.access_level;
      }
      // else: silently skip downgrade
    }
    if (updates.pivot_from !== undefined) existing.pivot_from = updates.pivot_from;
    if (updates.dvwa_available !== undefined) existing.dvwa_available = updates.dvwa_available;

    // Append-merge arrays (no duplicates)
    if (updates.services) {
      for (const s of updates.services) {
        if (!existing.services.includes(s)) existing.services.push(s);
      }
    }
    if (updates.vectors_open) {
      for (const v of updates.vectors_open) {
        if (!existing.vectors_open.includes(v)) existing.vectors_open.push(v);
      }
    }
    if (updates.vectors_blocked) {
      for (const v of updates.vectors_blocked) {
        if (!existing.vectors_blocked.includes(v)) existing.vectors_blocked.push(v);
        // Remove from open if now blocked
        const idx = existing.vectors_open.indexOf(v);
        if (idx !== -1) existing.vectors_open.splice(idx, 1);
      }
    }
    if (updates.response_times) {
      existing.response_times.push(...updates.response_times);
      existing.response_times = existing.response_times.slice(-RESPONSE_TIME_WINDOW);
    }
    if (updates.notes) {
      for (const n of updates.notes) {
        if (!existing.notes.includes(n)) existing.notes.push(n);
      }
    }

    existing.last_seen = new Date().toISOString();
    this.persist();
  }

  addEdge(from: string, to: string, via: string): void {
    const exists = this.graph.edges.some(
      (e) => e.from === from && e.to === to && e.via === via
    );
    if (!exists) {
      this.graph.edges.push({ from, to, via });
      // Mark 'from' as a pivot point if not already
      if (!this.graph.pivot_points.includes(from)) {
        this.graph.pivot_points.push(from);
      }
      this.persist();
    }
  }

  addTimeline(agent: string, action: string, result: string): void {
    this.graph.timeline.push({
      timestamp: new Date().toISOString(),
      agent,
      action,
      result,
    });
    this.persist();
  }

  queryNode(ip: string): AttackGraphNode | undefined {
    return this.graph.nodes[ip];
  }

  queryAll(): AttackGraph {
    return this.graph;
  }

  queryOpenVectors(ip?: string): Array<{ host: string; vectors: string[] }> {
    if (ip !== undefined) {
      const node = this.graph.nodes[ip];
      if (!node) return [];
      return [{ host: node.host, vectors: node.vectors_open }];
    }
    return Object.values(this.graph.nodes)
      .filter((n) => n.vectors_open.length > 0)
      .map((n) => ({ host: n.host, vectors: n.vectors_open }));
  }

  getBlocked(): string[] {
    return Object.values(this.graph.nodes)
      .filter((n) => n.status === 'blocked')
      .map((n) => n.ip);
  }

  recordResponseTime(ip: string, ms: number): void {
    const node = this.graph.nodes[ip];
    if (!node) return;
    node.response_times.push(ms);
    node.response_times = node.response_times.slice(-RESPONSE_TIME_WINDOW);
    this.persist();
  }

  detectBlock(ip: string): boolean {
    const node = this.graph.nodes[ip];
    if (!node) return false;

    const recent = node.response_times.slice(-BLOCK_DETECTION_WINDOW);
    if (recent.length < BLOCK_DETECTION_WINDOW) return false;

    const allBlocking = recent.every((t) => t === 0 || t >= BLOCK_THRESHOLD_MS);
    if (allBlocking) {
      node.status = 'blocked';
      this.persist();
      return true;
    }
    return false;
  }

  markDvwaUnavailable(ip: string): void {
    const node = this.graph.nodes[ip];
    if (!node) return;
    node.dvwa_available = false;
    if (!node.vectors_blocked.includes('dvwa')) {
      node.vectors_blocked.push('dvwa');
    }
    const idx = node.vectors_open.indexOf('dvwa');
    if (idx !== -1) node.vectors_open.splice(idx, 1);
    this.persist();
  }

  addSoarBlock(ip: string): void {
    if (!this.graph.soar_blocked_ips.includes(ip)) {
      this.graph.soar_blocked_ips.push(ip);
    }
    const node = this.graph.nodes[ip];
    if (node) {
      // v3.7.0 BUG-22: Set soar_status separately -- don't overwrite operational status
      // if host is already compromised (access_level > none)
      node.soar_status = 'blocked';
      if (node.access_level === 'none') {
        node.status = 'blocked';
      }
      // If host is compromised, keep status as 'up' -- it's reachable via pivot
    }
    this.persist();
  }

  getSummary(): string {
    const nodes = Object.values(this.graph.nodes);
    const total = nodes.length;
    const blocked = nodes.filter((n) => n.status === 'blocked').length;
    const pivots = this.graph.pivot_points.length;
    const openVectors = nodes.reduce((sum, n) => sum + n.vectors_open.length, 0);

    const lines = [
      `## Attack Graph Summary`,
      `- **Engagement:** ${this.graph.engagement_type}${this.graph.wan_ip ? ` (WAN: ${this.graph.wan_ip})` : ''}`,
      `- **Total hosts:** ${total}`,
      `- **Blocked:** ${blocked}`,
      `- **Pivot points:** ${pivots}`,
      `- **Open vectors (total):** ${openVectors}`,
      `- **SOAR-blocked IPs:** ${this.graph.soar_blocked_ips.join(', ') || 'none'}`,
    ];

    return lines.join('\n');
  }

  // v3: Query nodes by entity_type
  queryByEntityType(type: string): AttackGraphNode[] {
    return Object.values(this.graph.nodes).filter(
      (n) => (n as AttackGraphNode & { entity_type?: string }).entity_type === type,
    );
  }

  // v3: Deep clone for planner -- prevents mutation during planning
  getGraphSnapshot(): AttackGraph {
    return JSON.parse(JSON.stringify(this.graph));
  }

  // v3: Richer summary for planner prompts
  getDetailedSummary(): string {
    const nodes = Object.values(this.graph.nodes);
    const lines: string[] = [
      `# Attack Graph State`,
      ``,
      `## Overview`,
      `- Engagement: ${this.graph.engagement_type}`,
      `- Total hosts: ${nodes.length}`,
      `- Active hosts: ${nodes.filter(n => n.status === 'up').length}`,
      `- Blocked hosts: ${nodes.filter(n => n.status === 'blocked').length}`,
      `- Pivot points: ${this.graph.pivot_points.length}`,
      `- SOAR-blocked IPs: ${this.graph.soar_blocked_ips.join(', ') || 'none'}`,
      ``,
      `## Hosts`,
    ];

    for (const node of nodes) {
      lines.push(`### ${node.host} (${node.ip})`);
      lines.push(`- Status: ${node.status}`);
      lines.push(`- Access: ${node.access_level}`);
      if (node.services.length > 0) lines.push(`- Services: ${node.services.join(', ')}`);
      if (node.vectors_open.length > 0) lines.push(`- Open vectors: ${node.vectors_open.join(', ')}`);
      if (node.vectors_blocked.length > 0) lines.push(`- Blocked vectors: ${node.vectors_blocked.join(', ')}`);
      if (node.notes.length > 0) lines.push(`- Notes: ${node.notes.join('; ')}`);
      lines.push('');
    }

    if (this.graph.edges.length > 0) {
      lines.push(`## Edges`);
      for (const edge of this.graph.edges) {
        lines.push(`- ${edge.from} -> ${edge.to} via ${edge.via}`);
      }
      lines.push('');
    }

    if (this.graph.timeline.length > 0) {
      lines.push(`## Recent Timeline (last 10)`);
      for (const entry of this.graph.timeline.slice(-10)) {
        lines.push(`- [${entry.timestamp}] ${entry.agent}: ${entry.action} -> ${entry.result}`);
      }
    }

    return lines.join('\n');
  }

  // v3: Get viable attack vectors ordered by priority
  getViableVectors(): Array<{ host: string; ip: string; vectors: string[]; priority: number }> {
    return Object.values(this.graph.nodes)
      .filter(n => n.vectors_open.length > 0 && n.status !== 'blocked')
      .map(n => ({
        host: n.host,
        ip: n.ip,
        vectors: n.vectors_open,
        priority: this.computePriority(n),
      }))
      .sort((a, b) => b.priority - a.priority);
  }

  private computePriority(node: AttackGraphNode): number {
    let score = node.vectors_open.length;
    if (node.access_level === 'none') score += 2;
    if (node.access_level === 'user') score += 1;
    if (node.services.some(s => s.includes('445') || s.includes('5985'))) score += 2;
    if (node.dvwa_available) score += 1;
    return score;
  }

  toJSON(): string {
    return JSON.stringify(this.graph, null, 2);
  }

  private persist(): void {
    writeFileSync(this.graphPath, JSON.stringify(this.graph, null, 2));
  }
}
