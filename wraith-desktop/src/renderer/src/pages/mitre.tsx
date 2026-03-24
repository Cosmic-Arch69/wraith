
import { useState, useEffect, useCallback, useRef } from "react";
import { Shield, RefreshCw, Target, TrendingUp, Eye, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { MitreTechnique, MitreSeverity } from "@/lib/agent-types";
import { getTechniqueName, getTechniqueDescription } from "@/lib/mitre-techniques";

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------

const BASE_URL = "http://localhost:3001";

// 14 ATT&CK tactics in order
const TACTICS = [
  { id: "reconnaissance",        label: "Reconnaissance",        short: "Recon" },
  { id: "resource-development",  label: "Resource Development",  short: "Resource Dev" },
  { id: "initial-access",        label: "Initial Access",        short: "Initial Access" },
  { id: "execution",             label: "Execution",             short: "Execution" },
  { id: "persistence",           label: "Persistence",           short: "Persistence" },
  { id: "privilege-escalation",  label: "Privilege Escalation",  short: "Priv Esc" },
  { id: "defense-evasion",       label: "Defense Evasion",       short: "Def Evasion" },
  { id: "credential-access",     label: "Credential Access",     short: "Cred Access" },
  { id: "discovery",             label: "Discovery",             short: "Discovery" },
  { id: "lateral-movement",      label: "Lateral Movement",      short: "Lateral Mov" },
  { id: "collection",            label: "Collection",            short: "Collection" },
  { id: "command-and-control",   label: "Command & Control",     short: "C2" },
  { id: "exfiltration",          label: "Exfiltration",          short: "Exfil" },
  { id: "impact",                label: "Impact",                short: "Impact" },
] as const;

type TacticId = typeof TACTICS[number]["id"];

// Base technique ID -> tactic mapping
// A sub-technique like T1003.006 matches base T1003
const TECHNIQUE_TACTIC_MAP: Record<string, TacticId> = {
  // Reconnaissance
  T1595: "reconnaissance",
  T1592: "reconnaissance",
  T1046: "reconnaissance",
  T1590: "reconnaissance",
  T1591: "reconnaissance",
  // Resource Development
  T1583: "resource-development",
  T1584: "resource-development",
  T1587: "resource-development",
  T1588: "resource-development",
  // Initial Access
  T1190: "initial-access",
  T1133: "initial-access",
  T1200: "initial-access",
  T1078: "initial-access",
  // Execution
  T1059: "execution",
  T1047: "execution",
  T1053: "execution",
  // Persistence (T1053 shared, T1098/T1136 go here)
  T1098: "persistence",
  T1136: "persistence",
  // Privilege Escalation
  T1068: "privilege-escalation",
  T1548: "privilege-escalation",
  T1134: "privilege-escalation",
  // Defense Evasion
  T1562: "defense-evasion",
  T1070: "defense-evasion",
  T1036: "defense-evasion",
  // Credential Access
  T1110: "credential-access",
  T1003: "credential-access",
  T1558: "credential-access",
  T1187: "credential-access",
  T1552: "credential-access",
  T1555: "credential-access",
  T1649: "credential-access",
  // Discovery
  T1087: "discovery",
  T1018: "discovery",
  T1016: "discovery",
  T1069: "discovery",
  T1135: "discovery",
  T1201: "discovery",
  T1526: "discovery",
  T1482: "discovery",
  T1615: "discovery",
  // Lateral Movement
  T1021: "lateral-movement",
  T1550: "lateral-movement",
  T1090: "lateral-movement",
  // Collection
  T1005: "collection",
  T1560: "collection",
  // Command and Control
  T1071: "command-and-control",
  T1572: "command-and-control",
  // Exfiltration
  T1041: "exfiltration",
  // Impact
  T1486: "impact",
  T1489: "impact",
  T1529: "impact",
};

// T1053 appears in both Execution and Persistence -- default to Execution,
// but if a technique sub-ID is specifically persistence-related we can extend later.
// For now the first match wins via the map above.

// -----------------------------------------------------------------------
// Color helpers
// -----------------------------------------------------------------------

// Cell background based on success rate
function successRateBg(attempts: number, successes: number): string {
  if (attempts === 0) return "#141825"; // not attempted -- card bg
  const rate = successes / attempts;
  if (rate === 0)          return "#1a1f30"; // tried but 0% -- muted
  if (rate <= 0.25)        return "#2a2415"; // 1-25% -- dark amber
  if (rate <= 0.5)         return "#2d1f15"; // 26-50% -- dark orange
  if (rate <= 0.75)        return "#2d1519"; // 51-75% -- dark red
  return "#7f1d1d";                          // 76-100% -- deep red
}

// Left border stripe color for severity
function severityBorderColor(sev: MitreSeverity): string {
  switch (sev) {
    case "critical": return "#dc2626";
    case "high":     return "#f97316";
    case "medium":   return "#eab308";
    case "low":      return "#3b82f6";
    case "info":     return "#94a3b8";
  }
}

// Text color for success rate badge
function successRateTextColor(attempts: number, successes: number): string {
  if (attempts === 0) return "#9ca3af";
  const rate = successes / attempts;
  if (rate === 0)   return "#6b7280";
  if (rate <= 0.25) return "#92400e";
  if (rate <= 0.5)  return "#9a3412";
  if (rate <= 0.75) return "#991b1b";
  return "#7f1d1d";
}

const SEVERITY_ORDER: MitreSeverity[] = ["critical", "high", "medium", "low", "info"];

function severityRank(sev: MitreSeverity): number {
  return SEVERITY_ORDER.indexOf(sev);
}

// -----------------------------------------------------------------------
// API
// -----------------------------------------------------------------------

async function fetchHeatmap(): Promise<MitreTechnique[]> {
  const res = await fetch(`${BASE_URL}/api/mitre-heatmap`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  const data = (await res.json()) as unknown;
  if (typeof data !== "object" || data === null) return [];

  const raw = data as Record<string, unknown>;
  const arr = Array.isArray(raw.techniques)
    ? raw.techniques
    : Array.isArray(data)
      ? (data as unknown[])
      : [];

  return arr.map((item: unknown): MitreTechnique => {
    if (typeof item !== "object" || item === null) {
      return { id: "T0000", name: "Unknown", attempts: 0, successes: 0, blocks: 0, failures: 0, severity: "info", remediation: "" };
    }
    const t = item as Record<string, unknown>;

    // Normalize severity -- API may return "Informational" or "informational"
    const rawSev = String(t.severity ?? "info").toLowerCase();
    const normalizedSev = rawSev === "informational" ? "info" : rawSev;
    const severity: MitreSeverity = (["critical", "high", "medium", "low", "info"] as MitreSeverity[]).includes(normalizedSev as MitreSeverity)
      ? (normalizedSev as MitreSeverity)
      : "info";

    const attempts  = typeof t.attempts  === "number" ? t.attempts  : typeof t.count        === "number" ? t.count        : 0;
    const successes = typeof t.successes === "number" ? t.successes : typeof t.successCount  === "number" ? t.successCount : 0;

    return {
      id:         String(t.id ?? t.techniqueId ?? "T0000"),
      name:       getTechniqueName(String(t.id ?? t.techniqueId ?? "")) || String(t.name ?? t.techniqueName ?? "Unknown"),
      attempts,
      successes,
      blocks:     typeof t.blocks   === "number" ? t.blocks   : 0,
      failures:   typeof t.failures === "number" ? t.failures : attempts - successes,
      severity,
      remediation: String(t.remediation ?? ""),
      attackDetails:   typeof t.attackDetails   === "string" ? t.attackDetails   : undefined,
      affectedTargets: Array.isArray(t.affectedTargets) ? (t.affectedTargets as string[]) : undefined,
    };
  });
}

// -----------------------------------------------------------------------
// Technique -> tactic resolution
// -----------------------------------------------------------------------

function resolveBaseTechniqueId(id: string): string {
  // T1003.006 -> T1003
  const dot = id.indexOf(".");
  return dot === -1 ? id : id.slice(0, dot);
}

function getTacticForTechnique(id: string): TacticId | null {
  const base = resolveBaseTechniqueId(id);
  return TECHNIQUE_TACTIC_MAP[base] ?? null;
}

// Build a map of tacticId -> MitreTechnique[], sorted by severity then success rate desc
function buildTacticMap(
  techniques: MitreTechnique[],
  filterSeverity: string
): Map<TacticId, MitreTechnique[]> {
  const map = new Map<TacticId, MitreTechnique[]>();
  for (const tactic of TACTICS) {
    map.set(tactic.id, []);
  }

  for (const tech of techniques) {
    if (filterSeverity !== "all" && tech.severity !== filterSeverity) continue;
    const tactic = getTacticForTechnique(tech.id);
    if (tactic) {
      map.get(tactic)!.push(tech);
    }
  }

  // Sort each column: severity asc (critical first), then success rate desc
  for (const [, techs] of map) {
    techs.sort((a, b) => {
      const sevDiff = severityRank(a.severity) - severityRank(b.severity);
      if (sevDiff !== 0) return sevDiff;
      const aRate = a.attempts > 0 ? a.successes / a.attempts : 0;
      const bRate = b.attempts > 0 ? b.successes / b.attempts : 0;
      return bRate - aRate;
    });
  }

  return map;
}

// -----------------------------------------------------------------------
// Tooltip state
// -----------------------------------------------------------------------

interface TooltipState {
  technique: MitreTechnique;
  x: number;
  y: number;
}

// -----------------------------------------------------------------------
// Technique Cell
// -----------------------------------------------------------------------

interface TechniqueCellProps {
  technique: MitreTechnique;
  isExpanded: boolean;
  onExpand: (t: MitreTechnique | null) => void;
  onTooltip: (state: TooltipState | null) => void;
}

function TechniqueCell({ technique: t, isExpanded, onExpand, onTooltip }: TechniqueCellProps) {
  const successRate = t.attempts > 0 ? Math.round((t.successes / t.attempts) * 100) : 0;
  const bg          = successRateBg(t.attempts, t.successes);
  const borderLeft  = severityBorderColor(t.severity);
  const textColor   = successRateTextColor(t.attempts, t.successes);

  const handleMouseEnter = (e: React.MouseEvent) => {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    onTooltip({ technique: t, x: rect.right + 6, y: rect.top });
  };

  const handleMouseLeave = () => onTooltip(null);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onExpand(isExpanded ? null : t)}
      onKeyDown={(e) => e.key === "Enter" && onExpand(isExpanded ? null : t)}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        backgroundColor: isExpanded ? "#e0e7ff" : bg,
        borderLeft: `4px solid ${borderLeft}`,
        outline: isExpanded ? "2px solid #6366f1" : "none",
        outlineOffset: "-1px",
      }}
      className={cn(
        "w-full cursor-pointer select-none",
        "border-b border-border last:border-b-0",
        "px-2 py-1.5 transition-all duration-100",
        "hover:brightness-95"
      )}
    >
      <div className="flex items-baseline justify-between gap-1 min-w-0">
        <span
          className="font-mono text-[10px] font-semibold text-gray-200 shrink-0 leading-none"
        >
          {t.id}
        </span>
        <span
          className="font-mono text-[10px] font-semibold leading-none tabular-nums"
          style={{ color: textColor }}
        >
          {successRate}%
        </span>
      </div>
      <div className="mt-0.5 text-[9px] text-gray-400 leading-tight truncate max-w-full">
        {t.name}
      </div>
      {t.attempts > 0 && (
        <div className="mt-0.5 text-[9px] text-gray-400 leading-none">
          {t.attempts} att &middot; {t.successes} suc
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------
// Tactic Column
// -----------------------------------------------------------------------

interface TacticColumnProps {
  tacticId: TacticId;
  label: string;
  techniques: MitreTechnique[];
  expandedId: string | null;
  onExpand: (t: MitreTechnique | null) => void;
  onTooltip: (state: TooltipState | null) => void;
}

function TacticColumn({ tacticId, label, techniques, expandedId, onExpand, onTooltip }: TacticColumnProps) {
  const isEmpty = techniques.length === 0;

  return (
    <div
      className="flex flex-col shrink-0"
      style={{ width: 160 }}
    >
      {/* Column header */}
      <div
        style={{ backgroundColor: isEmpty ? "#94a3b8" : "#1e293b" }}
        className="px-2 py-2 rounded-t border border-b-0 border-border"
      >
        <div className="text-[11px] font-semibold text-white leading-tight">
          {label}
        </div>
        <div className="text-[10px] text-white/60 mt-0.5">
          {isEmpty ? "0 techniques" : `${techniques.length} technique${techniques.length !== 1 ? "s" : ""}`}
        </div>
      </div>

      {/* Cells */}
      <div
        className="flex-1 border border-border rounded-b overflow-hidden"
        style={{ minHeight: 40, backgroundColor: isEmpty ? "#111520" : "#141825" }}
      >
        {isEmpty ? (
          <div className="flex items-center justify-center h-10">
            <span className="text-[10px] text-gray-500 italic">none</span>
          </div>
        ) : (
          techniques.map((t) => (
            <TechniqueCell
              key={`${tacticId}-${t.id}`}
              technique={t}
              isExpanded={expandedId === t.id}
              onExpand={onExpand}
              onTooltip={onTooltip}
            />
          ))
        )}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Tooltip overlay
// -----------------------------------------------------------------------

function TechniqueTooltip({ state }: { state: TooltipState }) {
  const { technique: t, x, y } = state;
  const successRate = t.attempts > 0 ? Math.round((t.successes / t.attempts) * 100) : 0;

  // Clamp to viewport
  const tipWidth = 260;
  const clampedX = Math.min(x, window.innerWidth - tipWidth - 12);

  return (
    <div
      style={{
        position: "fixed",
        left: clampedX,
        top: y,
        width: tipWidth,
        zIndex: 9999,
        pointerEvents: "none",
      }}
      className="bg-gray-900 text-white rounded-lg shadow-2xl border border-gray-700 p-3 text-xs"
    >
      <div className="flex items-center gap-2 mb-2">
        <span className="font-mono font-bold text-indigo-300">{t.id}</span>
        <span
          className="text-[10px] px-1.5 py-0.5 rounded font-semibold uppercase"
          style={{
            backgroundColor: severityBorderColor(t.severity) + "33",
            color: severityBorderColor(t.severity),
          }}
        >
          {t.severity}
        </span>
      </div>
      <p className="text-gray-200 font-medium mb-1 leading-snug">{t.name}</p>
      <p className="text-[10px] text-gray-400 mb-2 leading-relaxed">{getTechniqueDescription(t.id)}</p>
      <div className="grid grid-cols-3 gap-1 mb-2 text-center">
        <div className="bg-gray-800 rounded p-1">
          <div className="text-[10px] text-gray-400">Attempts</div>
          <div className="font-mono font-bold text-white">{t.attempts}</div>
        </div>
        <div className="bg-gray-800 rounded p-1">
          <div className="text-[10px] text-gray-400">Successes</div>
          <div className="font-mono font-bold text-emerald-400">{t.successes}</div>
        </div>
        <div className="bg-gray-800 rounded p-1">
          <div className="text-[10px] text-gray-400">Rate</div>
          <div className="font-mono font-bold text-yellow-300">{successRate}%</div>
        </div>
      </div>
      {t.remediation && (
        <>
          <div className="text-[10px] text-gray-400 uppercase tracking-wider mb-1">Remediation</div>
          <p className="text-gray-300 leading-relaxed text-[11px] line-clamp-4">{t.remediation}</p>
        </>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------
// Expanded detail panel (below matrix)
// -----------------------------------------------------------------------

function ExpandedPanel({
  technique: t,
  onClose,
}: {
  technique: MitreTechnique;
  onClose: () => void;
}) {
  const successRate = t.attempts > 0 ? Math.round((t.successes / t.attempts) * 100) : 0;

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-4 mb-3">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="font-mono font-bold text-primary text-sm">{t.id}</span>
          <span className="text-gray-200 font-medium">{t.name}</span>
          <span
            className="text-[11px] px-2 py-0.5 rounded font-semibold uppercase"
            style={{
              backgroundColor: severityBorderColor(t.severity) + "22",
              color: severityBorderColor(t.severity),
              border: `1px solid ${severityBorderColor(t.severity)}55`,
            }}
          >
            {t.severity}
          </span>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="text-gray-400 hover:text-gray-100 shrink-0 mt-0.5"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Stats row */}
      <div className="flex gap-4 text-xs mb-3 flex-wrap">
        <span className="text-gray-400">Attempts: <span className="font-mono font-semibold text-gray-100">{t.attempts}</span></span>
        <span className="text-gray-400">Successes: <span className="font-mono font-semibold text-emerald-400">{t.successes}</span></span>
        <span className="text-gray-400">Blocks: <span className="font-mono font-semibold text-blue-400">{t.blocks}</span></span>
        <span className="text-gray-400">Success rate: <span className="font-mono font-semibold text-gray-100">{successRate}%</span></span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="md:col-span-1">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-1">Remediation</p>
          <p className="text-gray-300 leading-relaxed">{t.remediation || "No remediation provided."}</p>
        </div>
        <div className="md:col-span-1">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-1">Attack Details</p>
          <p className="text-gray-300 leading-relaxed">{t.attackDetails || "No additional details."}</p>
        </div>
        <div className="md:col-span-1">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-1">Affected Targets</p>
          {t.affectedTargets && t.affectedTargets.length > 0 ? (
            <ul className="space-y-0.5">
              {t.affectedTargets.map((ip) => (
                <li key={ip} className="font-mono text-gray-500">{ip}</li>
              ))}
            </ul>
          ) : (
            <p className="text-gray-400">None recorded.</p>
          )}
        </div>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Severity filter strip
// -----------------------------------------------------------------------

const SEVERITY_FILTERS: { value: string; label: string }[] = [
  { value: "all",      label: "All" },
  { value: "critical", label: "Critical" },
  { value: "high",     label: "High" },
  { value: "medium",   label: "Medium" },
  { value: "low",      label: "Low" },
  { value: "info",     label: "Info" },
];

// -----------------------------------------------------------------------
// Summary stat card
// -----------------------------------------------------------------------

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  valueColor,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string | number;
  sub?: string;
  valueColor?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-3 flex items-center gap-3 shadow-sm">
      <div className="rounded-md bg-secondary p-2 shrink-0">
        <Icon className="w-4 h-4 text-gray-400" />
      </div>
      <div className="min-w-0">
        <p className="text-[10px] text-gray-400 uppercase tracking-wider mb-0.5">{label}</p>
        <p
          className="text-lg font-semibold tabular-nums leading-none"
          style={{ color: valueColor ?? "#111827" }}
        >
          {value}
        </p>
        {sub && <p className="text-[10px] text-gray-400 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Legend row
// -----------------------------------------------------------------------

function Legend() {
  const items = [
    { bg: "#141825", border: "#1f2437", label: "Not attempted" },
    { bg: "#1a1f30", border: "#2a3045", label: "0% success" },
    { bg: "#2a2415", border: "#3a3425", label: "1-25%" },
    { bg: "#2d1f15", border: "#3d2f25", label: "26-50%" },
    { bg: "#2d1519", border: "#3d2529", label: "51-75%" },
    { bg: "#7f1d1d", border: "#991b1b", label: "76-100%" },
  ];

  const severities: { color: string; label: string }[] = [
    { color: "#dc2626", label: "Critical" },
    { color: "#f97316", label: "High" },
    { color: "#eab308", label: "Medium" },
    { color: "#3b82f6", label: "Low" },
    { color: "#94a3b8", label: "Info" },
  ];

  return (
    <div className="flex items-center gap-6 flex-wrap">
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-gray-400 uppercase tracking-wider shrink-0">Success rate:</span>
        {items.map((item) => (
          <div key={item.label} className="flex items-center gap-1">
            <div
              className="w-5 h-3 rounded-sm border"
              style={{ backgroundColor: item.bg, borderColor: item.border }}
            />
            <span className="text-[10px] text-gray-400">{item.label}</span>
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-gray-400 uppercase tracking-wider shrink-0">Severity stripe:</span>
        {severities.map((s) => (
          <div key={s.label} className="flex items-center gap-1">
            <div className="w-1 h-3 rounded-sm" style={{ backgroundColor: s.color }} />
            <span className="text-[10px] text-gray-400">{s.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Main page
// -----------------------------------------------------------------------

export default function MitrePage() {
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [expandedTechnique, setExpandedTechnique] = useState<MitreTechnique | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);

  const matrixRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchHeatmap();
      setTechniques(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load heatmap");
    } finally {
      setLoading(false);
      setLastRefreshed(new Date());
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  // Close tooltip on scroll
  useEffect(() => {
    const el = matrixRef.current;
    if (!el) return;
    const onScroll = () => setTooltip(null);
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, []);

  // Summary stats
  const totalAttempted  = techniques.filter((t) => t.attempts > 0).length;
  const totalSuccesses  = techniques.reduce((s, t) => s + t.successes, 0);
  const totalAttempts   = techniques.reduce((s, t) => s + t.attempts, 0);
  const totalBlocks     = techniques.reduce((s, t) => s + t.blocks, 0);
  const overallSuccessRate = totalAttempts > 0 ? Math.round((totalSuccesses / totalAttempts) * 100) : 0;
  const coveredTactics  = TACTICS.filter((tac) =>
    techniques.some((t) => getTacticForTechnique(t.id) === tac.id)
  ).length;

  const tacticMap = buildTacticMap(techniques, filterSeverity);

  const handleExpand = (t: MitreTechnique | null) => {
    setExpandedTechnique((prev) => (prev?.id === t?.id ? null : t));
    setTooltip(null);
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-primary" />
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-foreground">
              MITRE ATT&CK Matrix
            </h1>
            <p className="text-sm text-gray-400">
              Technique coverage mapped to the ATT&CK framework -- 14 tactics
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {lastRefreshed && (
            <span className="text-[11px] text-gray-400 font-mono">
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
            <RefreshCw className={cn("w-3 h-3", loading && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Summary stats */}
      {!loading && techniques.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard
            icon={Target}
            label="Techniques Attempted"
            value={totalAttempted}
            sub={`${totalAttempts} total attempts`}
          />
          <StatCard
            icon={TrendingUp}
            label="Overall Success Rate"
            value={`${overallSuccessRate}%`}
            sub={`${totalSuccesses} / ${totalAttempts} attempts`}
            valueColor={overallSuccessRate >= 50 ? "#dc2626" : overallSuccessRate >= 25 ? "#d97706" : "#16a34a"}
          />
          <StatCard
            icon={Eye}
            label="Blocks Recorded"
            value={totalBlocks}
            sub="detections / blocks"
            valueColor="#2563eb"
          />
          <StatCard
            icon={Shield}
            label="Tactics Covered"
            value={`${coveredTactics} / 14`}
            sub="ATT&CK tactic columns"
            valueColor="#7c3aed"
          />
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="flex items-center justify-center py-16 gap-3 text-gray-400">
          <Shield className="w-5 h-5 animate-pulse" />
          <span className="text-sm">Loading MITRE ATT&CK matrix...</span>
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-600">
          <p className="font-medium">Failed to load MITRE heatmap</p>
          <p className="text-xs mt-1 text-red-400">{error}</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && techniques.length === 0 && (
        <div className="rounded-lg border border-border bg-card p-10 text-center shadow-sm">
          <Shield className="w-8 h-8 mx-auto mb-3 text-gray-500" />
          <p className="text-sm text-gray-400">
            MITRE heatmap renders from{" "}
            <code className="text-xs font-mono bg-secondary px-1 py-0.5 rounded">
              /api/mitre-heatmap
            </code>{" "}
            generated by Wraith.
          </p>
          <p className="text-xs mt-1 text-gray-400">No data yet.</p>
        </div>
      )}

      {!loading && !error && techniques.length > 0 && (
        <>
          {/* Controls: severity filter + legend */}
          <div className="flex items-center gap-4 flex-wrap justify-between">
            {/* Severity filter */}
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[11px] text-gray-400 uppercase tracking-wider mr-1">Filter:</span>
              {SEVERITY_FILTERS.map((sev) => {
                const isActive = filterSeverity === sev.value;
                const color = sev.value === "all" ? "#6366f1"
                  : sev.value === "critical" ? "#dc2626"
                  : sev.value === "high"     ? "#f97316"
                  : sev.value === "medium"   ? "#eab308"
                  : sev.value === "low"      ? "#3b82f6"
                  : "#94a3b8";
                return (
                  <button
                    key={sev.value}
                    type="button"
                    onClick={() => {
                      setFilterSeverity(sev.value);
                      setExpandedTechnique(null);
                    }}
                    style={isActive ? { borderColor: color, color, backgroundColor: color + "15" } : {}}
                    className={cn(
                      "h-6 rounded border px-2.5 text-[11px] font-medium transition-all",
                      "focus-visible:outline-none",
                      isActive
                        ? "border-current"
                        : "border-border text-gray-400 hover:text-gray-100 hover:border-border"
                    )}
                  >
                    {sev.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Legend */}
          <Legend />

          {/* ATT&CK Navigator Matrix */}
          <div
            ref={matrixRef}
            className="overflow-x-auto rounded-lg border border-border bg-gray-50 p-3 shadow-sm"
            style={{ scrollbarWidth: "thin" }}
          >
            <div className="flex gap-2" style={{ width: "max-content", alignItems: "flex-start" }}>
              {TACTICS.map((tactic) => (
                <TacticColumn
                  key={tactic.id}
                  tacticId={tactic.id}
                  label={tactic.label}
                  techniques={tacticMap.get(tactic.id) ?? []}
                  expandedId={expandedTechnique?.id ?? null}
                  onExpand={handleExpand}
                  onTooltip={setTooltip}
                />
              ))}
            </div>
          </div>

          {/* Expanded technique panel */}
          {expandedTechnique && (
            <ExpandedPanel
              technique={expandedTechnique}
              onClose={() => setExpandedTechnique(null)}
            />
          )}
        </>
      )}

      {/* Floating tooltip */}
      {tooltip && <TechniqueTooltip state={tooltip} />}
    </div>
  );
}
