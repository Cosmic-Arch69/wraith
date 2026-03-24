
import { useEffect, useState, useCallback } from "react";
import {
  Clock,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  XCircle,
  Timer,
  User,
  KeyRound,
  Network,
  Shield,
} from "lucide-react";
import { getRoundResults } from "@/lib/api-extended";
import type { RoundResult, KillChainPhase, AgentSummary } from "@/lib/api-extended";
import { cn } from "@/lib/utils";

// -----------------------------------------------------------------------
// Kill chain config
// -----------------------------------------------------------------------

const KILL_CHAIN: { phase: KillChainPhase; label: string }[] = [
  { phase: "recon", label: "Recon" },
  { phase: "initial_access", label: "Initial Access" },
  { phase: "execution", label: "Execution" },
  { phase: "privesc", label: "Privesc" },
  { phase: "lateral_movement", label: "Lateral Movement" },
  { phase: "domain_compromise", label: "Domain Compromise" },
];

function KillChainBar({
  phasesReached,
}: {
  phasesReached: Set<KillChainPhase>;
}) {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-3">
      <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-3">
        Kill Chain Progress
      </p>
      <div className="flex items-center gap-0">
        {KILL_CHAIN.map(({ phase, label }, i) => {
          const reached = phasesReached.has(phase);
          return (
            <div key={phase} className="flex items-center">
              <div
                className={cn(
                  "flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium transition-colors",
                  reached
                    ? "bg-green-500/15 text-green-400 border border-green-500/30"
                    : "bg-zinc-800/60 text-zinc-500 border border-border"
                )}
              >
                {reached && (
                  <CheckCircle2 className="size-3 shrink-0 text-green-400" />
                )}
                {label}
              </div>
              {i < KILL_CHAIN.length - 1 && (
                <div
                  className={cn(
                    "h-px w-4 transition-colors",
                    reached ? "bg-green-500/50" : "bg-border"
                  )}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Relative time
// -----------------------------------------------------------------------

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function formatTs(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

// -----------------------------------------------------------------------
// Agent status icon
// -----------------------------------------------------------------------

function AgentStatusIcon({ status }: { status: AgentSummary["status"] }) {
  if (status === "success")
    return <CheckCircle2 className="size-3.5 text-green-400 shrink-0" />;
  if (status === "timeout")
    return <Timer className="size-3.5 text-yellow-400 shrink-0" />;
  return <XCircle className="size-3.5 text-red-400 shrink-0" />;
}

// -----------------------------------------------------------------------
// Round card
// -----------------------------------------------------------------------

function RoundCard({ round }: { round: RoundResult }) {
  const [expanded, setExpanded] = useState(false);

  const successCount = round.agents.filter((a) => a.status === "success").length;
  const failedCount = round.agents.filter((a) => a.status === "failed").length;
  const timeoutCount = round.agents.filter((a) => a.status === "timeout").length;

  const delta = round.graph_delta;
  const achievements: { icon: React.ReactNode; text: string }[] = [];

  if (delta?.credentials_gained && delta.credentials_gained.length > 0) {
    achievements.push({
      icon: <KeyRound className="size-3.5 text-yellow-400 shrink-0" />,
      text: `${delta.credentials_gained.length} credential${delta.credentials_gained.length !== 1 ? "s" : ""} gained (${delta.credentials_gained.join(", ")})`,
    });
  }
  if (delta?.access_levels_changed && delta.access_levels_changed.length > 0) {
    achievements.push({
      icon: <Shield className="size-3.5 text-primary shrink-0" />,
      text: `Access escalated on ${delta.access_levels_changed.length} host${delta.access_levels_changed.length !== 1 ? "s" : ""}`,
    });
  }
  if (delta?.vectors_opened && delta.vectors_opened.length > 0) {
    achievements.push({
      icon: <Network className="size-3.5 text-blue-400 shrink-0" />,
      text: `${delta.vectors_opened.length} new attack vector${delta.vectors_opened.length !== 1 ? "s" : ""} opened`,
    });
  }

  return (
    <div className="relative pl-8">
      {/* Timeline dot */}
      <div className="absolute left-0 top-4 w-4 h-4 rounded-full border-2 border-primary bg-background flex items-center justify-center">
        <div className="w-1.5 h-1.5 rounded-full bg-primary" />
      </div>
      {/* Vertical line (not on last item -- handled by parent) */}

      <div className="rounded-lg border border-border bg-card overflow-hidden">
        {/* Round header */}
        <button
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/30 transition-colors text-left"
          onClick={() => setExpanded((v) => !v)}
        >
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm font-bold text-primary">
              Round {round.id}
            </span>
            <span className="text-xs text-muted-foreground font-mono">
              {formatTs(round.startedAt)}
            </span>
            <span className="text-xs text-muted-foreground">
              {relativeTime(round.startedAt)}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-muted-foreground font-mono">
              {round.agents.length} agent{round.agents.length !== 1 ? "s" : ""}
              {" "}
              <span className="text-green-400">{successCount} ok</span>
              {failedCount > 0 && (
                <span className="text-red-400"> {failedCount} fail</span>
              )}
              {timeoutCount > 0 && (
                <span className="text-yellow-400"> {timeoutCount} timeout</span>
              )}
            </span>
            {expanded ? (
              <ChevronDown className="size-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="size-4 text-muted-foreground" />
            )}
          </div>
        </button>

        {/* Key achievements */}
        {achievements.length > 0 && (
          <div className="border-t border-border/50 px-4 py-2.5">
            <ul className="flex flex-col gap-1.5">
              {achievements.map((a, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-foreground/80">
                  {a.icon}
                  <span>{a.text}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Plan summary */}
        {round.planSummary && (
          <div className="border-t border-border/50 px-4 py-2.5">
            <p className="text-xs text-muted-foreground leading-relaxed">
              {round.planSummary}
            </p>
          </div>
        )}

        {/* Expanded agent list */}
        {expanded && round.agents.length > 0 && (
          <div className="border-t border-border bg-muted/10">
            <div className="px-4 py-2 flex items-center gap-1.5">
              <User className="size-3 text-muted-foreground" />
              <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Agent Summaries
              </span>
            </div>
            <div className="divide-y divide-border/30">
              {round.agents.map((agent, i) => (
                <div
                  key={agent.agentId ?? i}
                  className="px-4 py-2.5 flex items-start gap-2"
                >
                  <AgentStatusIcon status={agent.status} />
                  <div className="flex flex-col gap-0.5 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-medium text-foreground">
                        {agent.agentId}
                      </span>
                      {agent.tool && (
                        <span className="text-xs text-muted-foreground bg-muted/60 rounded px-1.5 py-0.5">
                          {agent.tool}
                        </span>
                      )}
                      {agent.target && (
                        <span className="font-mono text-xs text-muted-foreground">
                          {agent.target}
                        </span>
                      )}
                    </div>
                    {agent.summary && (
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        {agent.summary}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Main page
// -----------------------------------------------------------------------

export default function TimelinePage() {
  const [rounds, setRounds] = useState<RoundResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await getRoundResults();
      // Most recent first
      const sorted = [...data].sort((a, b) => b.id - a.id);
      setRounds(sorted);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load timeline");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Collect all phases reached across all rounds
  const allPhasesReached = new Set<KillChainPhase>(
    rounds.flatMap((r) => r.phases_reached ?? [])
  );

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Clock className="w-5 h-5 text-primary" />
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-foreground">
            Attack Timeline
          </h1>
          <p className="text-sm text-muted-foreground">
            Chronological view of every attack round
          </p>
        </div>
      </div>

      {/* Kill chain bar always at top */}
      <KillChainBar phasesReached={allPhasesReached} />

      {/* Timeline */}
      {loading ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          Loading timeline...
        </div>
      ) : error ? (
        <div className="rounded-lg border border-destructive/30 bg-card p-6 text-center text-sm text-destructive">
          {error}
        </div>
      ) : rounds.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          <Clock className="w-8 h-8 mx-auto mb-2 text-muted-foreground/40" />
          <p>Timeline populates when an engagement has run at least one round.</p>
        </div>
      ) : (
        <div className="relative flex flex-col gap-4">
          {/* Continuous vertical line */}
          <div className="absolute left-2 top-4 bottom-4 w-px bg-border" />

          {rounds.map((round) => (
            <RoundCard key={round.id} round={round} />
          ))}
        </div>
      )}
    </div>
  );
}
