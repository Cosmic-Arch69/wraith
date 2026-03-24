import type {
  GraphData,
  AttackResult,
  Round,
  Credential,
  MitreHeatmap,
  AgentOutput,
  ReportData,
  EngagementStatus,
} from "@/lib/types";

const BASE_URL =
  "http://localhost:3001";

// -----------------------------------------------------------------------
// Generic fetch helper with typed error handling
// -----------------------------------------------------------------------

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
    ...init,
    // No server-side caching by default -- engagement data is live
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`[Wraith API] ${res.status} ${path}: ${text}`);
  }

  return res.json() as Promise<T>;
}

// -----------------------------------------------------------------------
// Typed API functions
// -----------------------------------------------------------------------

/** Full graph snapshot (nodes + edges). */
export async function getGraph(): Promise<GraphData> {
  return apiFetch<GraphData>("/api/graph");
}

/** All attack results, optionally filtered by round. */
export async function getAttacks(roundId?: number): Promise<AttackResult[]> {
  const qs = roundId !== undefined ? `?roundId=${roundId}` : "";
  return apiFetch<AttackResult[]>(`/api/attacks${qs}`);
}

/** All rounds with summary stats. */
export async function getRounds(): Promise<Round[]> {
  return apiFetch<Round[]>("/api/rounds");
}

/** All harvested credentials. */
export async function getCredentials(): Promise<Credential[]> {
  return apiFetch<Credential[]>("/api/credentials");
}

/** MITRE ATT&CK heatmap data. */
export async function getMitreHeatmap(): Promise<MitreHeatmap> {
  return apiFetch<MitreHeatmap>("/api/mitre-heatmap");
}

/**
 * Agent output for a specific agent+round.
 * Pass only agentId to get all rounds for that agent.
 */
export async function getAgentOutput(
  agentId: string,
  roundId?: number
): Promise<AgentOutput[]> {
  const qs = roundId !== undefined ? `?roundId=${roundId}` : "";
  return apiFetch<AgentOutput[]>(`/api/agents/${agentId}/output${qs}`);
}

/** All agent IDs seen during the engagement. */
export async function getAgentIds(): Promise<string[]> {
  return apiFetch<string[]>("/api/agents");
}

/** Full engagement report data. */
export async function getReport(): Promise<ReportData> {
  return apiFetch<ReportData>("/api/report");
}

/** Current engagement status and phase. */
export async function getEngagementStatus(): Promise<EngagementStatus> {
  return apiFetch<EngagementStatus>("/api/status");
}

/** SSE stream URL -- used by useWraithSse hook. */
export function getSseUrl(): string {
  return `${BASE_URL}/api/events`;
}
