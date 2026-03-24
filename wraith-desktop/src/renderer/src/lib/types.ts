// -----------------------------------------------------------------------
// Wraith Console -- shared type definitions
// These mirror the data structures emitted by the Wraith backend.
// -----------------------------------------------------------------------

export type AccessLevel =
  | "none"
  | "discovered"
  | "credentials"
  | "user"
  | "admin"
  | "system"
  | "domain_admin"
  | "domain_controller";

export type NodeType =
  | "host"
  | "domain_controller"
  | "workstation"
  | "server"
  | "web"
  | "database"
  | "kali";

export type EdgeType =
  | "network"
  | "exploit"
  | "lateral"
  | "credential"
  | "trust";

export type AttackStatus = "success" | "failure" | "partial" | "error";

export type EngagementPhase =
  | "idle"
  | "recon"
  | "attack"
  | "reporting"
  | "complete";

// -----------------------------------------------------------------------
// Graph
// -----------------------------------------------------------------------

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  ip?: string;
  os?: string;
  accessLevel: AccessLevel;
  services?: string[];
  tags?: string[];
  // layout hints (set by react-flow or backend)
  x?: number;
  y?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  label?: string;
  roundId?: number;
  timestamp?: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  updatedAt: string;
}

// -----------------------------------------------------------------------
// Attacks / Rounds
// -----------------------------------------------------------------------

export interface AttackResult {
  id: string;
  roundId: number;
  agentId: string;
  target: string;
  tool: string;
  status: AttackStatus;
  output?: string;
  credential?: string;
  timestamp: string;
  durationMs?: number;
  mitreId?: string;
  mitreTactic?: string;
}

export interface Round {
  id: number;
  startedAt: string;
  completedAt?: string;
  attackCount: number;
  successCount: number;
  failureCount: number;
  newCredentials: number;
  planSummary?: string;
}

// -----------------------------------------------------------------------
// Credentials
// -----------------------------------------------------------------------

export interface Credential {
  id: string;
  username: string;
  domain?: string;
  hash?: string;
  plaintext?: string;
  type: "ntlm" | "kerberos" | "cleartext" | "certificate";
  source: string;
  foundAt: string;
  usedIn?: string[];
}

// -----------------------------------------------------------------------
// MITRE ATT&CK
// -----------------------------------------------------------------------

export interface MitreTechniqueHeat {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  count: number;
  successCount: number;
  lastSeen?: string;
}

export interface MitreHeatmap {
  tactics: string[];
  techniques: MitreTechniqueHeat[];
  generatedAt: string;
}

// -----------------------------------------------------------------------
// Agent output
// -----------------------------------------------------------------------

export interface AgentOutput {
  agentId: string;
  roundId: number;
  prompt?: string;
  response?: string;
  toolCalls?: ToolCallRecord[];
  startedAt: string;
  completedAt?: string;
  tokenCount?: number;
}

export interface ToolCallRecord {
  tool: string;
  input: Record<string, unknown>;
  output?: string;
  durationMs?: number;
}

// -----------------------------------------------------------------------
// Report
// -----------------------------------------------------------------------

export interface ReportData {
  engagementId: string;
  target: string;
  domain?: string;
  summary: string;
  findings: Finding[];
  recommendations: string[];
  timeline: AttackResult[];
  generatedAt: string;
  markdownPath?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  evidence?: string;
  remediation?: string;
  mitreIds?: string[];
}

// -----------------------------------------------------------------------
// Engagement status
// -----------------------------------------------------------------------

export interface EngagementStatus {
  engagementId?: string;
  phase: EngagementPhase;
  currentRound?: number;
  maxRounds?: number;
  startTime?: string;
  target?: string;
  domain?: string;
}

// -----------------------------------------------------------------------
// SSE event types
// -----------------------------------------------------------------------

export type SseEventType =
  | "status"
  | "graph_update"
  | "attack_result"
  | "round_complete"
  | "credential_found"
  | "agent_output"
  | "mitre_update"
  | "error"
  | "heartbeat";

export interface SseEvent {
  type: SseEventType;
  data: unknown;
  timestamp: string;
}

// -----------------------------------------------------------------------
// Attack stats aggregate
// -----------------------------------------------------------------------

export interface AttackStats {
  total: number;
  success: number;
  failure: number;
  partial: number;
  successRate: number;
}
