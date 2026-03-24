
import { useState, useEffect, useCallback, useRef } from "react";
import { Bot, ChevronDown, ChevronRight, RefreshCw } from "lucide-react";
import { AgentCard } from "@/components/agents/agent-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type {
  AgentMeta,
  AgentStatus,
  AgentTemplate,
  RoundWithAgents,
} from "@/lib/agent-types";

// -----------------------------------------------------------------------
// API helpers
// -----------------------------------------------------------------------

const BASE_URL =
  "http://localhost:3001";

async function safeFetch<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return null;
    return res.json() as Promise<T>;
  } catch {
    return null;
  }
}

// Normalise whatever the backend sends into AgentMeta[]
// Backend may return round objects with nested agent_results, or a flat agent list
function normaliseAgents(raw: unknown): AgentMeta[] {
  if (!Array.isArray(raw)) return [];

  return raw.flatMap((item: unknown): AgentMeta[] => {
    if (typeof item !== "object" || item === null) return [];
    const r = item as Record<string, unknown>;

    // Round shape: { id, agent_results: [...] } or { id, agents: [...] }
    const agentArray = r.agent_results ?? r.agents;
    if (Array.isArray(agentArray)) {
      const roundId = typeof r.id === "number" ? r.id : 0;
      return agentArray.flatMap((a: unknown) => {
        if (typeof a !== "object" || a === null) return [];
        return [toAgentMeta(a as Record<string, unknown>, roundId)];
      });
    }

    // Flat agent shape
    if ("agentId" in r || "agent_id" in r || "id" in r) {
      return [toAgentMeta(r, 0)];
    }

    return [];
  });
}

function toAgentMeta(
  r: Record<string, unknown>,
  fallbackRoundId: number
): AgentMeta {
  const agentId =
    String(r.agentId ?? r.agent_id ?? r.id ?? "unknown-agent");
  const roundId =
    typeof r.roundId === "number"
      ? r.roundId
      : typeof r.round_id === "number"
        ? r.round_id
        : fallbackRoundId;

  const rawStatus = String(r.status ?? "").toLowerCase();
  const status: AgentStatus = (
    ["success", "failed", "timeout", "refused", "no_findings", "running"] as AgentStatus[]
  ).includes(rawStatus as AgentStatus)
    ? (rawStatus as AgentStatus)
    : "failed";

  // Extract template from agent ID if template field is partial (e.g., "auth" instead of "auth-attack")
  let rawTemplate = String(r.template ?? "other").toLowerCase();
  if (rawTemplate.length <= 4 && agentId.includes('-r')) {
    // Parse from agent ID: "auth-attack-r1-10.0.0.183" -> "auth-attack"
    const match = agentId.match(/^(.+?)-r\d/);
    if (match) rawTemplate = match[1].toLowerCase();
  }
  const template: AgentTemplate = (
    [
      "sqli", "lateral", "privesc", "recon", "exploit", "bruteforce",
      "exfil", "persistence", "auth-attack", "cmdi", "kerberoast",
      "pivot", "nuclei",
    ] as AgentTemplate[]
  ).includes(rawTemplate as AgentTemplate)
    ? (rawTemplate as AgentTemplate)
    : "other";

  return {
    agentId,
    roundId,
    template,
    target: (() => {
      const t = String(r.target ?? r.ip ?? "");
      // If target looks like "r1-10.0.0.183-pfsense", extract the IP
      const ipMatch = t.match(/(\d+\.\d+\.\d+\.\d+)/);
      return ipMatch ? ipMatch[1] : (t || "--");
    })(),
    status,
    turns: typeof r.turns === "number" ? r.turns : 0,
    durationMs: typeof r.durationMs === "number"
      ? r.durationMs
      : typeof r.duration_ms === "number"
        ? r.duration_ms
        : 0,
    credentialsFound:
      typeof r.credentialsFound === "number"
        ? r.credentialsFound
        : typeof r.credentials_found === "number"
          ? r.credentials_found
          : 0,
    evidenceFiles: Array.isArray(r.evidenceFiles)
      ? (r.evidenceFiles as string[])
      : Array.isArray(r.evidence_files)
        ? (r.evidence_files as string[])
        : [],
    spawnedAt:
      typeof r.spawnedAt === "string"
        ? r.spawnedAt
        : typeof r.spawned_at === "string"
          ? r.spawned_at
          : typeof r.startedAt === "string"
            ? r.startedAt
            : new Date().toISOString(),
    completedAt:
      typeof r.completedAt === "string"
        ? r.completedAt
        : typeof r.completed_at === "string"
          ? r.completed_at
          : undefined,
  };
}

function groupByRound(agents: AgentMeta[]): RoundWithAgents[] {
  const map = new Map<number, AgentMeta[]>();
  for (const a of agents) {
    if (!map.has(a.roundId)) map.set(a.roundId, []);
    map.get(a.roundId)!.push(a);
  }
  // Most recent round first
  return Array.from(map.entries())
    .sort(([a], [b]) => b - a)
    .map(([roundId, roundAgents]) => ({
      roundId,
      startedAt: roundAgents[0]?.spawnedAt ?? "",
      completedAt: roundAgents.every((a) => a.completedAt)
        ? roundAgents
            .map((a) => a.completedAt!)
            .sort()
            .at(-1)
        : undefined,
      agents: roundAgents.sort(
        (a, b) =>
          new Date(b.spawnedAt).getTime() - new Date(a.spawnedAt).getTime()
      ),
    }));
}

// -----------------------------------------------------------------------
// Filter types
// -----------------------------------------------------------------------

type SortKey = "spawn" | "duration" | "turns";

// -----------------------------------------------------------------------
// Round group row
// -----------------------------------------------------------------------

function RoundGroup({
  round,
  filterStatus,
  filterTemplate,
  sortKey,
}: {
  round: RoundWithAgents;
  filterStatus: string;
  filterTemplate: string;
  sortKey: SortKey;
}) {
  const [open, setOpen] = useState(true);

  const filtered = round.agents
    .filter((a) => {
      if (filterStatus !== "all" && a.status !== filterStatus) return false;
      if (filterTemplate !== "all" && a.template !== filterTemplate) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortKey === "duration") return b.durationMs - a.durationMs;
      if (sortKey === "turns") return b.turns - a.turns;
      return (
        new Date(b.spawnedAt).getTime() - new Date(a.spawnedAt).getTime()
      );
    });

  const running = filtered.filter((a) => a.status === "running").length;
  const success = filtered.filter((a) => a.status === "success").length;

  return (
    <div className="space-y-2">
      {/* Round header */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-1 py-1 text-left group"
      >
        {open ? (
          <ChevronDown className="w-4 h-4 text-muted-foreground/60 group-hover:text-muted-foreground transition-colors" />
        ) : (
          <ChevronRight className="w-4 h-4 text-muted-foreground/60 group-hover:text-muted-foreground transition-colors" />
        )}
        <span className="text-xs font-semibold text-muted-foreground tracking-wide uppercase">
          Round {round.roundId}
        </span>
        <div className="flex items-center gap-2 ml-1">
          <Badge
            variant="outline"
            className="text-[10px] px-1.5 py-0 border-border text-muted-foreground"
          >
            {filtered.length} agent{filtered.length !== 1 ? "s" : ""}
          </Badge>
          {running > 0 && (
            <Badge
              variant="outline"
              className="text-[10px] px-1.5 py-0 bg-blue-500/10 text-blue-400 border-blue-500/25"
            >
              {running} running
            </Badge>
          )}
          {success > 0 && (
            <Badge
              variant="outline"
              className="text-[10px] px-1.5 py-0 bg-emerald-500/10 text-emerald-400 border-emerald-500/25"
            >
              {success} success
            </Badge>
          )}
        </div>
        <div className="h-px flex-1 bg-border/60" />
      </button>

      {/* Agent cards grid */}
      {open && filtered.length > 0 && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3 pl-0">
          {filtered.map((agent) => (
            <AgentCard key={`${agent.agentId}:${agent.roundId}`} agent={agent} />
          ))}
        </div>
      )}

      {open && filtered.length === 0 && (
        <p className="text-xs text-muted-foreground pl-7 py-2">
          No agents match the current filters.
        </p>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------
// SSE integration for live agent:spawn / agent:complete
// -----------------------------------------------------------------------

function useLiveAgentUpdates(
  onSpawn: (agent: AgentMeta) => void,
  onComplete: (agent: AgentMeta) => void
) {
  const onSpawnRef = useRef(onSpawn);
  const onCompleteRef = useRef(onComplete);
  onSpawnRef.current = onSpawn;
  onCompleteRef.current = onComplete;

  useEffect(() => {
    const url = `${BASE_URL}/api/events`;
    let es: EventSource;

    try {
      es = new EventSource(url);

      es.addEventListener("agent:spawn", (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data as string) as unknown;
          if (typeof data === "object" && data !== null) {
            const meta = toAgentMeta(data as Record<string, unknown>, 0);
            meta.status = "running";
            onSpawnRef.current(meta);
          }
        } catch {
          // ignore parse errors
        }
      });

      es.addEventListener("agent:complete", (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data as string) as unknown;
          if (typeof data === "object" && data !== null) {
            const meta = toAgentMeta(data as Record<string, unknown>, 0);
            onCompleteRef.current(meta);
          }
        } catch {
          // ignore parse errors
        }
      });
    } catch {
      // SSE not available -- silent fail
    }

    return () => {
      try {
        es?.close();
      } catch {
        // ignore
      }
    };
  }, []);
}

// -----------------------------------------------------------------------
// Page
// -----------------------------------------------------------------------

const ALL_STATUSES: AgentStatus[] = [
  "success",
  "failed",
  "timeout",
  "refused",
  "no_findings",
  "running",
];

const ALL_TEMPLATES: AgentTemplate[] = [
  "sqli",
  "lateral",
  "privesc",
  "recon",
  "exploit",
  "bruteforce",
  "exfil",
  "persistence",
  "other",
];

export default function AgentsPage() {
  const [agents, setAgents] = useState<AgentMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  // Filters
  const [filterRound, setFilterRound] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterTemplate, setFilterTemplate] = useState<string>("all");
  const [sortKey, setSortKey] = useState<SortKey>("spawn");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Try /api/rounds first (has agent_results arrays), fall back to /api/agents
      const rounds = await safeFetch<unknown>(`${BASE_URL}/api/rounds`);
      if (rounds !== null) {
        setAgents(normaliseAgents(rounds));
      } else {
        const agentList = await safeFetch<unknown>(`${BASE_URL}/api/agents`);
        setAgents(agentList !== null ? normaliseAgents(agentList) : []);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load agents");
    } finally {
      setLoading(false);
      setLastRefreshed(new Date());
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // SSE live updates
  useLiveAgentUpdates(
    (spawned) => {
      setAgents((prev) => {
        const exists = prev.find(
          (a) => a.agentId === spawned.agentId && a.roundId === spawned.roundId
        );
        if (exists) return prev;
        return [...prev, spawned];
      });
    },
    (completed) => {
      setAgents((prev) =>
        prev.map((a) =>
          a.agentId === completed.agentId && a.roundId === completed.roundId
            ? { ...a, ...completed }
            : a
        )
      );
    }
  );

  const rounds = groupByRound(agents);
  const availableRounds = rounds.map((r) => r.roundId);

  const filteredRounds =
    filterRound === "all"
      ? rounds
      : rounds.filter((r) => r.roundId === parseInt(filterRound, 10));

  return (
    <div className="flex flex-col gap-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bot className="w-5 h-5 text-primary" />
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-foreground">
              Agent Monitor
            </h1>
            <p className="text-sm text-muted-foreground">
              Live agent execution, tool calls, and LLM output
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {lastRefreshed && (
            <span className="text-[11px] text-muted-foreground/60 font-mono">
              {lastRefreshed.toLocaleTimeString()}
            </span>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => void load()}
            disabled={loading}
            className="gap-1.5 text-xs h-7"
          >
            <RefreshCw
              className={cn("w-3 h-3", loading && "animate-spin")}
            />
            Refresh
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Round filter */}
        <FilterSelect
          label="Round"
          value={filterRound}
          onChange={setFilterRound}
          options={[
            { value: "all", label: "All rounds" },
            ...availableRounds.map((id) => ({
              value: String(id),
              label: `R${id}`,
            })),
          ]}
        />

        {/* Status filter */}
        <FilterSelect
          label="Status"
          value={filterStatus}
          onChange={setFilterStatus}
          options={[
            { value: "all", label: "All statuses" },
            ...ALL_STATUSES.map((s) => ({
              value: s,
              label: s.charAt(0).toUpperCase() + s.slice(1).replace("_", " "),
            })),
          ]}
        />

        {/* Template filter */}
        <FilterSelect
          label="Template"
          value={filterTemplate}
          onChange={setFilterTemplate}
          options={[
            { value: "all", label: "All templates" },
            ...ALL_TEMPLATES.map((t) => ({
              value: t,
              label: t,
            })),
          ]}
        />

        {/* Sort */}
        <FilterSelect
          label="Sort by"
          value={sortKey}
          onChange={(v) => setSortKey(v as SortKey)}
          options={[
            { value: "spawn", label: "Spawn time" },
            { value: "duration", label: "Duration" },
            { value: "turns", label: "Turns" },
          ]}
        />

        {/* Agent count */}
        <span className="ml-auto text-[11px] text-muted-foreground/70 font-mono">
          {agents.length} agent{agents.length !== 1 ? "s" : ""} total
        </span>
      </div>

      {/* Content */}
      {loading && (
        <div className="flex items-center justify-center py-16 gap-3 text-muted-foreground">
          <Bot className="w-5 h-5 animate-pulse" />
          <span className="text-sm">Loading agents...</span>
        </div>
      )}

      {!loading && error && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">
          <p className="font-medium">Failed to load agents</p>
          <p className="text-xs mt-1 text-red-400/70">{error}</p>
        </div>
      )}

      {!loading && !error && agents.length === 0 && (
        <div className="rounded-lg border border-border bg-card p-10 text-center">
          <Bot className="w-8 h-8 mx-auto mb-3 text-muted-foreground/30" />
          <p className="text-sm text-muted-foreground">
            Agent output streams here during an active engagement.
          </p>
          <p className="text-xs mt-1 text-muted-foreground/60">
            No agents recorded yet.
          </p>
        </div>
      )}

      {!loading && !error && filteredRounds.length > 0 && (
        <div className="space-y-6">
          {filteredRounds.map((round) => (
            <RoundGroup
              key={round.roundId}
              round={round}
              filterStatus={filterStatus}
              filterTemplate={filterTemplate}
              sortKey={sortKey}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------
// Inline filter select -- avoids importing Select (not in ui dir)
// -----------------------------------------------------------------------

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[11px] text-muted-foreground/60 uppercase tracking-wider">
        {label}:
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          "h-7 rounded-md border border-border bg-secondary/50 px-2 text-xs text-foreground",
          "focus:outline-none focus:ring-2 focus:ring-ring/50",
          "cursor-pointer"
        )}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value} className="bg-zinc-900">
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
}
