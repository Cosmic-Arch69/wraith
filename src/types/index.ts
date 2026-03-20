// Core type definitions for Wraith

export type AgentName =
  | 'osint-recon'
  | 'recon'
  | 'sqli'
  | 'cmdi'
  | 'auth-attack'
  | 'kerberoast'
  | 'bruteforce'
  | 'lateral'
  | 'privesc'
  | 'report';

export type ModelTier = 'small' | 'medium' | 'large';

export type AttackResult = 'success' | 'failed' | 'blocked' | 'skipped';

export type EngagementType = 'external' | 'internal' | 'assumed-breach';

export type CredentialScope = 'web' | 'domain' | 'local' | 'unknown';

export type CredentialSource =
  | 'sqli'
  | 'spray'
  | 'kerberoast'
  | 'asrep'
  | 'lsass'
  | 'dcsync'
  | 'config'
  | 'responder'
  | 'unknown';

// v2.1: Shared credential across all agents
export interface Credential {
  id: string;                        // uuid or hash of username+password
  username: string;
  password?: string;
  hash?: string;                     // NTLM or Kerberos hash
  source: CredentialSource;
  scope: CredentialScope;
  hosts_valid: string[];             // IPs where this cred worked
  hosts_failed: string[];            // IPs where it failed
  protocol_valid: string[];          // smb, winrm, rdp, http, ldap
  protocol_failed: string[];
  discovered_at: string;             // ISO-8601
}

// v2.1: Attack graph node representing a discovered host
export interface AttackGraphNode {
  host: string;                      // hostname or IP
  ip: string;
  status: 'up' | 'down' | 'blocked' | 'unknown';
  services: string[];                // e.g. ['smb:445', 'http:3000', 'winrm:5985']
  access_level: 'none' | 'user' | 'admin' | 'system';
  pivot_from?: string;               // IP we pivoted through to reach this host
  vectors_open: string[];            // attack vectors still viable
  vectors_blocked: string[];         // attack vectors confirmed dead
  dvwa_available?: boolean;          // v2.1 F10
  response_times: number[];          // last N response times in ms (0 = timeout)
  last_seen: string;                 // ISO-8601
  notes: string[];                   // arbitrary findings
}

// v2.1: Live attack graph shared across all agents
export interface AttackGraph {
  engagement_type: EngagementType;
  wan_ip?: string;
  nodes: Record<string, AttackGraphNode>;   // keyed by IP
  edges: Array<{ from: string; to: string; via: string }>;
  pivot_points: string[];                   // IPs with internal access post-pivot
  soar_blocked_ips: string[];               // IPs SOAR has blocked us from
  timeline: Array<{
    timestamp: string;
    agent: string;
    action: string;
    result: string;
  }>;
}

export interface AgentDefinition {
  name: AgentName;
  displayName: string;
  prerequisites: AgentName[];
  promptTemplate: string;
  deliverableFilename: string;
  modelTier?: ModelTier;
  usePlaywright?: boolean;
  timeout_sec?: number;              // v2.1 F4: wall-clock timeout
}

export interface AttackEvent {
  timestamp: string;
  phase: string;
  technique: string;
  techniqueName: string;
  target: {
    ip: string;
    user?: string;
    service?: string;
    url?: string;
  };
  sourceIp: string;
  tool: string;
  result: AttackResult;
  wazuhRuleExpected: string;
  details: string;
}

export interface WraithConfig {
  engagement?: {
    type: EngagementType;
    wan_ip?: string;                 // for external mode: pfSense WAN IP
    network_interface?: string;      // B6: network interface for Responder (default: 'eth0')
    name?: string;
  };
  target: {
    domain: string;
    dc: string;
    hosts: Array<{
      ip: string;
      name: string;
      web_url?: string;
      web_app?: string;
    }>;
    credentials: {
      domain_user: string;
      domain_pass: string;
      web_dvwa_user?: string;
      web_dvwa_pass?: string;
    };
  };
  attack: {
    randomize: boolean;
    delay_min_sec: number;
    delay_max_sec: number;
    phases: number[];
    timeouts?: Record<string, number>;  // v2.1 F4: wall-clock seconds per agent
  };
  output: {
    log_dir: string;
    report: boolean;
  };
}

// ============================================================================
// v3 Types -- Adaptive Pipeline
// ============================================================================

export type AgentId = string;

// Ontology types -- generated from recon by LLM
export interface AttackOntology {
  entity_types: OntologyEntityType[];
  edge_types: OntologyEdgeType[];
  generated_at: string;
}
export interface OntologyEntityType {
  name: string;
  description: string;
  attributes: OntologyAttribute[];
  examples: string[];
}
export interface OntologyEdgeType {
  name: string;
  description: string;
  source_types: string[];
  target_types: string[];
}
export interface OntologyAttribute {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'string[]';
  description: string;
}

// Agent profiles -- planner generates these
export interface AgentProfile {
  id: AgentId;
  technique: string;          // MITRE ATT&CK ID
  technique_name: string;
  target_ip: string;
  target_service?: string;
  prompt_template: string;    // from AGENT_TEMPLATE_LIBRARY
  model_tier: ModelTier;
  turn_budget: number;
  timeout_sec: number;
  priority: number;           // 1-10
  stealth_level: 'loud' | 'moderate' | 'quiet';
  depends_on: AgentId[];
  context_vars: Record<string, string>;
}

// Action plan -- planner output
export interface ActionPlan {
  round: number;
  agents_to_spawn: AgentProfile[];
  agents_to_skip: Array<{ id: AgentId; reason: string }>;
  objective_status: 'in_progress' | 'achieved' | 'blocked' | 'budget_exhausted';
  reasoning: string;
  next_milestone: string;
}

// Round results -- evaluator output
export interface RoundResult {
  round: number;
  started_at: string;
  completed_at: string;
  agent_results: AgentRoundResult[];
  graph_delta: GraphDelta;
}
export interface AgentRoundResult {
  agent_id: AgentId;
  success: boolean;
  result_summary: string;
  duration_ms: number;
  turns_used: number;
  evidence_files: string[];
  credentials_found: number;
  vectors_opened: string[];
  vectors_blocked: string[];
}
export interface GraphDelta {
  nodes_added: string[];
  nodes_updated: string[];
  edges_added: number;
  vectors_opened: string[];
  vectors_closed: string[];
  credentials_gained: number;
  access_levels_changed: Array<{ ip: string; from: string; to: string }>;
}

// Budget tracking
export interface BudgetState {
  max_rounds: number;
  rounds_used: number;
  max_total_agents: number;
  agents_spawned: number;
  max_concurrent: number;
}

// Report types
export interface ReportOutline {
  title: string;
  executive_summary: string;
  sections: Array<{ title: string; description: string }>;
}

// v3 config extension
export interface WraithV3Config extends WraithConfig {
  planning?: {
    max_rounds: number;
    max_total_agents: number;
    max_concurrent_agents: number;
    objective?: string;
    stealth_mode?: boolean;
  };
  report?: {
    react_max_iterations: number;
    react_min_tool_calls: number;
  };
}
