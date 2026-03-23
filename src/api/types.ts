// v3.7.0: Console API contract definitions
// Typed interfaces for what the Wraith Console (v4.0.0) will consume
// No HTTP server in v3.7.0 -- just the contracts + event bus

import type {
  AgentRoundResult,
  AttackGraph,
  Credential,
  Finding,
  FindingSeverity,
  RoundResult,
  WraithV3Config,
} from '../types/index.js';

// ---- SSE Event Types ----

export type SSEEventType =
  | 'round:start'
  | 'round:complete'
  | 'agent:spawn'
  | 'agent:complete'
  | 'agent:heartbeat'
  | 'attack:logged'
  | 'graph:update'
  | 'credential:discovered'
  | 'soar:detected'
  | 'pipeline:phase'
  | 'pipeline:complete';

export interface SSEEvent {
  type: SSEEventType;
  timestamp: string;
  data: unknown;
}

// ---- REST Endpoint Contracts ----

// GET /api/engagement
export interface EngagementStatus {
  version: string;
  config: Partial<WraithV3Config>;
  state: 'initializing' | 'preflight' | 'recon' | 'scanning' | 'ontology' | 'attacking' | 'reporting' | 'complete';
  currentRound: number;
  maxRounds: number;
  agentsSpawned: number;
  maxAgents: number;
  startedAt: string;
  elapsedMs: number;
}

// GET /api/attacks/stats
export interface AttackStats {
  totalAttempted: number;
  totalSucceeded: number;
  totalFailed: number;
  totalBlocked: number;
  totalSkipped: number;
  soarDetectionRate: number;
  byTechnique: Record<string, { attempts: number; successes: number; blocks: number }>;
  byPhase: Record<string, { attempts: number; successes: number }>;
}

// GET /api/mitre-heatmap
export interface MITREHeatmap {
  tactics: MITRETactic[];
}

export interface MITRETactic {
  id: string;
  name: string;
  techniques: MITRETechniqueEntry[];
}

export interface MITRETechniqueEntry {
  id: string;
  name: string;
  attempts: number;
  successes: number;
  severity: FindingSeverity;
}

// GET /api/detection-matrix (Blue Team Tab)
export interface DetectionMatrixEntry {
  technique: string;
  techniqueName: string;
  targetIp: string;
  wazuhRuleExpected: string;
  wazuhRuleTriggered: boolean;
  soarActionTaken: boolean;
  soarResponseTimeMs?: number;
  details: string;
}

// ---- Re-exports for Console convenience ----
export type {
  AgentRoundResult,
  AttackGraph,
  Credential,
  Finding,
  RoundResult,
};
