// -----------------------------------------------------------------------
// Agent Monitor -- extended types for the agents view
// These extend the base types with API shapes returned by the backend.
// -----------------------------------------------------------------------

export type AgentStatus =
  | "success"
  | "failed"
  | "timeout"
  | "refused"
  | "no_findings"
  | "running";

export type AgentTemplate =
  | "sqli"
  | "lateral"
  | "privesc"
  | "recon"
  | "exploit"
  | "bruteforce"
  | "exfil"
  | "persistence"
  | "auth-attack"
  | "cmdi"
  | "kerberoast"
  | "pivot"
  | "nuclei"
  | "other";

export interface AgentMeta {
  agentId: string;
  roundId: number;
  template: AgentTemplate;
  target: string;
  status: AgentStatus;
  turns: number;
  durationMs: number;
  credentialsFound: number;
  evidenceFiles: string[];
  spawnedAt: string;
  completedAt?: string;
}

export interface RoundWithAgents {
  roundId: number;
  startedAt: string;
  completedAt?: string;
  agents: AgentMeta[];
}

// -----------------------------------------------------------------------
// MITRE extended types for the heatmap view
// -----------------------------------------------------------------------

export type MitreSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface MitreTechnique {
  id: string;
  name: string;
  attempts: number;
  successes: number;
  blocks: number;
  failures: number;
  severity: MitreSeverity;
  remediation: string;
  attackDetails?: string;
  affectedTargets?: string[];
}

export interface MitreHeatmapResponse {
  techniques: MitreTechnique[];
}
