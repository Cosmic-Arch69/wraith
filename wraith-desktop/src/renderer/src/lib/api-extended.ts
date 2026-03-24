// Extended API types and fetch functions for views not covered by the base API

const BASE_URL =
  "http://localhost:3001";

async function apiFetchExtended<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
    ...init,
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`[Wraith API] ${res.status} ${path}: ${text}`);
  }

  return res.json() as Promise<T>;
}

// -----------------------------------------------------------------------
// Credentials view types
// -----------------------------------------------------------------------

export type CredentialSource =
  | "sqli"
  | "spray"
  | "kerberoast"
  | "dcsync"
  | "lsass"
  | "config";

export type CredentialScope = "domain" | "web" | "local";

export interface CredentialRow {
  id: string;
  username: string;
  password?: string;
  hash?: string;
  source: CredentialSource;
  scope: CredentialScope;
  hosts_valid: string[];
  hosts_failed: string[];
  discovered_at: string;
}

export async function getCredentialRows(): Promise<CredentialRow[]> {
  return apiFetchExtended<CredentialRow[]>("/api/credentials");
}

// -----------------------------------------------------------------------
// Findings view types
// -----------------------------------------------------------------------

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface FindingRow {
  id: string;
  title: string;
  severity: FindingSeverity;
  technique: string;
  techniqueName: string;
  attempts: number;
  successes: number;
  remediation: string;
}

export async function getFindingRows(): Promise<FindingRow[]> {
  return apiFetchExtended<FindingRow[]>("/api/findings");
}

// -----------------------------------------------------------------------
// Timeline view types
// -----------------------------------------------------------------------

export type KillChainPhase =
  | "recon"
  | "initial_access"
  | "execution"
  | "privesc"
  | "lateral_movement"
  | "domain_compromise";

export interface GraphDelta {
  access_levels_changed?: Array<{ host: string; from: string; to: string }>;
  vectors_opened?: string[];
  credentials_gained?: string[];
}

export interface AgentSummary {
  agentId: string;
  status: "success" | "failed" | "timeout";
  summary: string;
  tool?: string;
  target?: string;
}

export interface RoundResult {
  id: number;
  startedAt: string;
  completedAt?: string;
  agents: AgentSummary[];
  graph_delta?: GraphDelta;
  phases_reached?: KillChainPhase[];
  planSummary?: string;
}

export async function getRoundResults(): Promise<RoundResult[]> {
  return apiFetchExtended<RoundResult[]>("/api/rounds");
}

// -----------------------------------------------------------------------
// Report
// -----------------------------------------------------------------------

export async function getReportMarkdown(): Promise<string> {
  const res = await fetch(`${BASE_URL}/api/report`, {
    cache: "no-store",
  });

  if (res.status === 404) {
    throw new NotFoundError("Report not available");
  }

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`[Wraith API] ${res.status} /api/report: ${text}`);
  }

  return res.text();
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}
