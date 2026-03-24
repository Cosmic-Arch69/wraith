
import { useEffect, useCallback, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  LayoutDashboard,
  Key,
  Swords,
  CheckCircle2,
  XCircle,
  Ban,
  ChevronRight,
  ExternalLink,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  RadialBarChart,
  RadialBar,
  PolarAngleAxis,
} from "recharts";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AttackGraphCanvas } from "@/components/graph/attack-graph-canvas";
import { useEngagementStore } from "@/stores/engagement-store";
import { useWraithSse } from "@/hooks/use-wraith-sse";
import {
  getGraph,
  getRounds,
  getCredentials,
  getAttacks,
  getEngagementStatus,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import type { SseEventType, EngagementPhase } from "@/lib/types";

// -----------------------------------------------------------------------
// Pipeline phases
// -----------------------------------------------------------------------

const PHASES: EngagementPhase[] = [
  "idle",
  "recon",
  "attack",
  "reporting",
  "complete",
];

const phaseLabels: Record<EngagementPhase, string> = {
  idle: "Idle",
  recon: "Recon",
  attack: "Attack Loop",
  reporting: "Report",
  complete: "Complete",
};

// -----------------------------------------------------------------------
// Live feed event type colors/labels
// -----------------------------------------------------------------------

const eventStyles: Record<
  SseEventType | "default",
  { bg: string; text: string; label: string }
> = {
  status: { bg: "bg-blue-900/40", text: "text-blue-300", label: "STATUS" },
  graph_update: {
    bg: "bg-violet-900/40",
    text: "text-violet-300",
    label: "GRAPH",
  },
  attack_result: {
    bg: "bg-red-900/40",
    text: "text-red-300",
    label: "ATTACK",
  },
  round_complete: {
    bg: "bg-amber-900/40",
    text: "text-amber-300",
    label: "ROUND",
  },
  credential_found: {
    bg: "bg-emerald-900/40",
    text: "text-emerald-300",
    label: "CRED",
  },
  agent_output: {
    bg: "bg-zinc-800",
    text: "text-zinc-300",
    label: "AGENT",
  },
  error: { bg: "bg-red-900/60", text: "text-red-300", label: "ERR" },
  heartbeat: { bg: "bg-zinc-800", text: "text-zinc-500", label: "HB" },
  mitre_update: { bg: "bg-purple-900/40", text: "text-purple-300", label: "MITRE" },
  default: { bg: "bg-zinc-800", text: "text-zinc-400", label: "EVT" },
};

// -----------------------------------------------------------------------
// Feed event shape
// -----------------------------------------------------------------------

interface FeedEvent {
  id: string;
  type: SseEventType;
  description: string;
  timestamp: string;
}

// -----------------------------------------------------------------------
// Custom recharts tooltip
// -----------------------------------------------------------------------

function CustomBarTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name: string; value: number; fill: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs font-mono shadow-xl">
      <p className="text-zinc-300 mb-1">{label}</p>
      {payload.map((p) => (
        <p key={p.name} style={{ color: p.fill }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
}

// -----------------------------------------------------------------------
// Circular progress ring (pure CSS + SVG -- no recharts needed)
// -----------------------------------------------------------------------

function RoundProgressRing({
  current,
  max,
}: {
  current: number;
  max: number;
}) {
  const pct = max > 0 ? current / max : 0;
  const r = 32;
  const circ = 2 * Math.PI * r;
  const dashOffset = circ * (1 - pct);

  return (
    <svg width={80} height={80} className="-rotate-90">
      <circle
        cx={40}
        cy={40}
        r={r}
        fill="none"
        stroke="#27272a"
        strokeWidth={6}
      />
      <circle
        cx={40}
        cy={40}
        r={r}
        fill="none"
        stroke="#ef4444"
        strokeWidth={6}
        strokeDasharray={circ}
        strokeDashoffset={dashOffset}
        strokeLinecap="round"
        className="transition-all duration-700"
      />
    </svg>
  );
}

// -----------------------------------------------------------------------
// Dashboard page
// -----------------------------------------------------------------------

export default function DashboardPage() {
  // Activate SSE connection
  useWraithSse();

  const engagementStatus = useEngagementStore((s) => s.engagementStatus);
  const graph = useEngagementStore((s) => s.graph);
  const rounds = useEngagementStore((s) => s.rounds);
  const credentials = useEngagementStore((s) => s.credentials);
  const recentAttacks = useEngagementStore((s) => s.recentAttacks);
  const attackStats = useEngagementStore((s) => s.attackStats);
  const setGraph = useEngagementStore((s) => s.setGraph);
  const setRounds = useEngagementStore((s) => s.setRounds);
  const setCredentials = useEngagementStore((s) => s.setCredentials);
  const setRecentAttacks = useEngagementStore((s) => s.setRecentAttacks);
  const setEngagementStatus = useEngagementStore((s) => s.setEngagementStatus);

  const [feedEvents, setFeedEvents] = useState<FeedEvent[]>([]);
  const feedRef = useRef<HTMLDivElement>(null);
  const feedIdRef = useRef(0);

  // -----------------------------------------------------------------------
  // Initial data fetch
  // -----------------------------------------------------------------------

  const fetchAll = useCallback(async () => {
    await Promise.allSettled([
      getGraph().then(setGraph).catch(() => {}),
      getRounds().then(setRounds).catch(() => {}),
      getCredentials().then(setCredentials).catch(() => {}),
      getAttacks().then(setRecentAttacks).catch(() => {}),
      getEngagementStatus().then(setEngagementStatus).catch(() => {}),
    ]);
  }, [setGraph, setRounds, setCredentials, setRecentAttacks, setEngagementStatus]);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 10000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  // -----------------------------------------------------------------------
  // SSE listener for live feed -- uses Zustand v5 subscribe (1-arg form)
  // -----------------------------------------------------------------------

  useEffect(() => {
    let prevAttackLen = useEngagementStore.getState().recentAttacks.length;
    let prevCredLen = useEngagementStore.getState().credentials.length;
    let prevRoundLen = useEngagementStore.getState().rounds.length;

    const unsub = useEngagementStore.subscribe((state) => {
      const attacks = state.recentAttacks;
      const creds = state.credentials;
      const rounds = state.rounds;

      // New attacks
      if (attacks.length > prevAttackLen) {
        const newAttacks = attacks.slice(prevAttackLen);
        prevAttackLen = attacks.length;
        setFeedEvents((evts) => {
          const newEvts: FeedEvent[] = newAttacks.map((a) => ({
            id: `atk-${feedIdRef.current++}`,
            type: "attack_result" as SseEventType,
            description: `[${a.status.toUpperCase()}] ${a.tool} on ${a.target}${a.mitreId ? ` (${a.mitreId})` : ""}`,
            timestamp: a.timestamp,
          }));
          return [...evts, ...newEvts].slice(-50);
        });
      }

      // New credentials
      if (creds.length > prevCredLen) {
        const newCreds = creds.slice(prevCredLen);
        prevCredLen = creds.length;
        setFeedEvents((evts) => {
          const newEvts: FeedEvent[] = newCreds.map((c) => ({
            id: `cred-${feedIdRef.current++}`,
            type: "credential_found" as SseEventType,
            description: `Credential found: ${c.username}${c.domain ? `@${c.domain}` : ""} [${c.type}]`,
            timestamp: c.foundAt,
          }));
          return [...evts, ...newEvts].slice(-50);
        });
      }

      // New rounds
      if (rounds.length > prevRoundLen) {
        const latest = rounds[rounds.length - 1];
        prevRoundLen = rounds.length;
        if (latest) {
          setFeedEvents((evts) =>
            [
              ...evts,
              {
                id: `rnd-${feedIdRef.current++}`,
                type: "round_complete" as SseEventType,
                description: `Round ${latest.id} complete -- ${latest.successCount} success, ${latest.failureCount} fail`,
                timestamp: latest.completedAt ?? latest.startedAt,
              },
            ].slice(-50)
          );
        }
      }
    });

    return unsub;
  }, []);

  // Auto-scroll feed
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [feedEvents]);

  // -----------------------------------------------------------------------
  // Derived values
  // -----------------------------------------------------------------------

  const phase = engagementStatus?.phase ?? "idle";
  const currentRound = engagementStatus?.currentRound ?? 0;
  const maxRounds = engagementStatus?.maxRounds ?? 0;

  // Build bar chart data from recent attacks grouped by tool/technique
  const barData = useMemo_attackBarData(recentAttacks);

  // Agent stats from rounds
  const totalAgents = rounds.reduce((sum, r) => sum + r.attackCount, 0);
  const succeededAgents = rounds.reduce((sum, r) => sum + r.successCount, 0);
  const failedAgents = rounds.reduce((sum, r) => sum + r.failureCount, 0);

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  return (
    <div className="flex flex-col gap-5">
      {/* Page header */}
      <div className="flex items-center gap-3">
        <LayoutDashboard className="w-5 h-5 text-primary" />
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-foreground">
            Dashboard
          </h1>
          <p className="text-sm text-muted-foreground">
            Engagement overview and live stats
          </p>
        </div>
        {engagementStatus?.target && (
          <div className="ml-auto text-xs font-mono text-muted-foreground">
            target:{" "}
            <span className="text-foreground">{engagementStatus.target}</span>
          </div>
        )}
      </div>

      {/* Row 1 -- Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Phase card */}
        <Card className="ring-1 ring-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs uppercase tracking-widest text-muted-foreground font-medium">
              Phase
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="flex flex-wrap gap-1">
              {PHASES.map((p, i) => (
                <div key={p} className="flex items-center gap-1">
                  <span
                    className={cn(
                      "text-[10px] font-mono px-1.5 py-0.5 rounded",
                      p === phase
                        ? "bg-primary/20 text-primary border border-primary/30"
                        : "text-zinc-600"
                    )}
                  >
                    {phaseLabels[p]}
                  </span>
                  {i < PHASES.length - 1 && (
                    <ChevronRight className="w-2.5 h-2.5 text-zinc-700" />
                  )}
                </div>
              ))}
            </div>
            <div className="mt-2 text-xs text-muted-foreground">
              Current:{" "}
              <span className="text-primary font-semibold">
                {phaseLabels[phase]}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Rounds card */}
        <Card className="ring-1 ring-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs uppercase tracking-widest text-muted-foreground font-medium">
              Rounds
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="flex items-center gap-3">
              <RoundProgressRing current={currentRound} max={maxRounds || 1} />
              <div>
                <div className="text-2xl font-bold font-mono text-foreground tabular-nums">
                  {currentRound}
                  {maxRounds > 0 && (
                    <span className="text-base text-muted-foreground">
                      /{maxRounds}
                    </span>
                  )}
                </div>
                <div className="text-xs text-muted-foreground">
                  {maxRounds > 0
                    ? `${Math.round((currentRound / maxRounds) * 100)}% done`
                    : "no limit set"}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Agents card */}
        <Card className="ring-1 ring-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs uppercase tracking-widest text-muted-foreground font-medium">
              Agents
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="text-2xl font-bold font-mono text-foreground tabular-nums">
              {totalAgents}
            </div>
            <div className="flex items-center gap-3 mt-2 text-xs">
              <div className="flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                <span className="text-emerald-400 font-mono">{succeededAgents}</span>
              </div>
              <div className="flex items-center gap-1">
                <XCircle className="w-3 h-3 text-red-500" />
                <span className="text-red-400 font-mono">{failedAgents}</span>
              </div>
              <div className="flex items-center gap-1">
                <Ban className="w-3 h-3 text-violet-500" />
                <span className="text-violet-400 font-mono">
                  {Math.max(0, totalAgents - succeededAgents - failedAgents)}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Credentials card */}
        <Card className="ring-1 ring-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs uppercase tracking-widest text-muted-foreground font-medium">
              Credentials
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="flex items-center gap-2">
              <Key className="w-6 h-6 text-amber-500" />
              <div>
                <div className="text-2xl font-bold font-mono text-foreground tabular-nums">
                  {credentials.length}
                </div>
                <div className="text-xs text-muted-foreground">harvested</div>
              </div>
            </div>
            {credentials.length > 0 && (
              <div className="flex gap-1.5 mt-2 flex-wrap">
                {["ntlm", "kerberos", "cleartext", "certificate"].map((t) => {
                  const count = credentials.filter((c) => c.type === t).length;
                  if (!count) return null;
                  return (
                    <span
                      key={t}
                      className="text-[9px] font-mono bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded"
                    >
                      {t}: {count}
                    </span>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row 2 -- Feed + Mini graph */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Live activity feed (60%) */}
        <Card className="lg:col-span-3 ring-1 ring-foreground/10">
          <CardHeader className="border-b border-border pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs uppercase tracking-widest text-muted-foreground font-medium">
                Live Activity Feed
              </CardTitle>
              <span className="text-[10px] font-mono text-zinc-600">
                {feedEvents.length} events
              </span>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div
              ref={feedRef}
              className="h-64 overflow-y-auto scrollbar-thin font-mono text-xs"
            >
              {feedEvents.length === 0 ? (
                <div className="flex items-center justify-center h-full text-zinc-600">
                  Waiting for events...
                </div>
              ) : (
                <div className="divide-y divide-zinc-800/60">
                  {feedEvents.map((evt) => {
                    const style =
                      eventStyles[evt.type] ?? eventStyles.default;
                    return (
                      <div
                        key={evt.id}
                        className="flex items-start gap-2 px-4 py-2 hover:bg-zinc-900/50 transition-colors"
                      >
                        <span className="text-zinc-600 tabular-nums shrink-0 pt-0.5">
                          {new Date(evt.timestamp).toLocaleTimeString(
                            "en-US",
                            {
                              hour12: false,
                              hour: "2-digit",
                              minute: "2-digit",
                              second: "2-digit",
                            }
                          )}
                        </span>
                        <span
                          className={cn(
                            "shrink-0 px-1.5 py-0 rounded text-[9px] tracking-wider",
                            style.bg,
                            style.text
                          )}
                        >
                          {style.label}
                        </span>
                        <span className="text-zinc-300 break-all">
                          {evt.description}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Mini attack graph (40%) */}
        <Card className="lg:col-span-2 ring-1 ring-foreground/10">
          <CardHeader className="border-b border-border pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs uppercase tracking-widest text-muted-foreground font-medium">
                Attack Graph
              </CardTitle>
              <Link
                to="/graph"
                className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                Full view <ExternalLink className="w-2.5 h-2.5" />
              </Link>
            </div>
          </CardHeader>
          <CardContent className="p-0 h-64">
            <Link to="/graph" className="block h-full cursor-pointer group">
              <div className="h-full relative rounded-b-xl overflow-hidden">
                <AttackGraphCanvas graph={graph} compact />
                {/* Hover overlay */}
                <div className="absolute inset-0 bg-zinc-950/0 group-hover:bg-zinc-950/20 transition-colors flex items-end justify-center pb-3 opacity-0 group-hover:opacity-100">
                  <span className="text-xs text-white bg-zinc-900/80 px-3 py-1 rounded-full border border-zinc-700">
                    Open full graph
                  </span>
                </div>
              </div>
            </Link>
          </CardContent>
        </Card>
      </div>

      {/* Row 3 -- Attack stats bar chart */}
      <Card className="ring-1 ring-foreground/10">
        <CardHeader className="border-b border-border pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs uppercase tracking-widest text-muted-foreground font-medium">
              Attack Stats by Technique
            </CardTitle>
            <div className="flex items-center gap-4 text-xs text-muted-foreground">
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm bg-emerald-600" />
                <span>Success</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm bg-red-700" />
                <span>Failure</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm bg-zinc-600" />
                <span>Blocked</span>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent className="pt-4">
          {barData.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-zinc-600 text-sm">
              No attack data yet
            </div>
          ) : (
            <div className="flex items-center gap-6 mb-4">
              <StatPill
                label="Total"
                value={attackStats.total}
                color="text-foreground"
              />
              <StatPill
                label="Success"
                value={attackStats.success}
                color="text-emerald-400"
              />
              <StatPill
                label="Failure"
                value={attackStats.failure}
                color="text-red-400"
              />
              <StatPill
                label="Rate"
                value={`${attackStats.successRate}%`}
                color="text-amber-400"
              />
            </div>
          )}
          <ResponsiveContainer width="100%" height={180}>
            <BarChart
              data={barData}
              margin={{ top: 0, right: 0, bottom: 0, left: -20 }}
              barSize={8}
              barGap={2}
            >
              <XAxis
                dataKey="tool"
                tick={{ fontSize: 10, fill: "#71717a", fontFamily: "monospace" }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 10, fill: "#52525b", fontFamily: "monospace" }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip
                content={
                  <CustomBarTooltip />
                }
                cursor={{ fill: "rgba(255,255,255,0.03)" }}
              />
              <Bar dataKey="success" name="Success" fill="#059669" radius={[2, 2, 0, 0]} />
              <Bar dataKey="failure" name="Failure" fill="#b91c1c" radius={[2, 2, 0, 0]} />
              <Bar dataKey="blocked" name="Blocked" fill="#52525b" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
}

// -----------------------------------------------------------------------
// Helper components
// -----------------------------------------------------------------------

function StatPill({
  label,
  value,
  color,
}: {
  label: string;
  value: string | number;
  color: string;
}) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] text-muted-foreground uppercase tracking-widest">
        {label}
      </span>
      <span className={cn("text-xl font-bold font-mono tabular-nums", color)}>
        {value}
      </span>
    </div>
  );
}

// -----------------------------------------------------------------------
// Build bar chart data from recent attacks
// -----------------------------------------------------------------------

import type { AttackResult } from "@/lib/types";

function useMemo_attackBarData(attacks: AttackResult[]) {
  if (attacks.length === 0) return [];

  const toolMap: Record<
    string,
    { success: number; failure: number; blocked: number }
  > = {};

  for (const a of attacks) {
    const key = a.tool ?? "unknown";
    if (!toolMap[key]) toolMap[key] = { success: 0, failure: 0, blocked: 0 };
    if (a.status === "success") toolMap[key].success++;
    else if (a.status === "failure") toolMap[key].failure++;
    else if (a.status === "partial") toolMap[key].blocked++;
  }

  return Object.entries(toolMap)
    .map(([tool, stats]) => ({ tool, ...stats }))
    .sort((a, b) => b.success + b.failure - (a.success + a.failure))
    .slice(0, 12);
}
