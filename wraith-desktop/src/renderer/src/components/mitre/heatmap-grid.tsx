
import { Fragment, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { MitreTechnique, MitreSeverity } from "@/lib/agent-types";

// -----------------------------------------------------------------------
// Severity styling
// -----------------------------------------------------------------------

const severityConfig: Record<
  MitreSeverity,
  { label: string; rowBg: string; badgeClass: string; dotClass: string }
> = {
  critical: {
    label: "Critical",
    rowBg: "bg-red-900/20 hover:bg-red-900/30",
    badgeClass: "bg-red-500/15 text-red-400 border border-red-500/25",
    dotClass: "bg-red-500",
  },
  high: {
    label: "High",
    rowBg: "bg-orange-900/20 hover:bg-orange-900/30",
    badgeClass:
      "bg-orange-500/15 text-orange-400 border border-orange-500/25",
    dotClass: "bg-orange-500",
  },
  medium: {
    label: "Medium",
    rowBg: "bg-yellow-900/20 hover:bg-yellow-900/30",
    badgeClass:
      "bg-yellow-500/15 text-yellow-400 border border-yellow-500/25",
    dotClass: "bg-yellow-500",
  },
  low: {
    label: "Low",
    rowBg: "bg-blue-900/20 hover:bg-blue-900/30",
    badgeClass: "bg-blue-500/15 text-blue-400 border border-blue-500/25",
    dotClass: "bg-blue-400",
  },
  info: {
    label: "Info",
    rowBg: "bg-zinc-800/40 hover:bg-zinc-800/60",
    badgeClass: "bg-zinc-700/40 text-zinc-400 border border-zinc-600/30",
    dotClass: "bg-zinc-500",
  },
};

// -----------------------------------------------------------------------
// Cell intensity -- darker = more attempts
// -----------------------------------------------------------------------

function cellIntensity(attempts: number, maxAttempts: number): string {
  if (maxAttempts === 0) return "opacity-20";
  const ratio = attempts / maxAttempts;
  if (ratio >= 0.8) return "opacity-100";
  if (ratio >= 0.6) return "opacity-80";
  if (ratio >= 0.4) return "opacity-60";
  if (ratio >= 0.2) return "opacity-40";
  return "opacity-25";
}

function cellSuccessBorder(successes: number, attempts: number): string {
  if (attempts === 0) return "border-zinc-700/30";
  const rate = successes / attempts;
  if (rate >= 0.6) return "border-emerald-500/70";
  if (rate >= 0.3) return "border-yellow-500/60";
  return "border-red-500/50";
}

// -----------------------------------------------------------------------
// Visual cell grid
// -----------------------------------------------------------------------

interface CellGridProps {
  techniques: MitreTechnique[];
  onSelect: (t: MitreTechnique) => void;
  selectedId: string | null;
}

export function CellGrid({ techniques, onSelect, selectedId }: CellGridProps) {
  const maxAttempts = Math.max(...techniques.map((t) => t.attempts), 1);

  return (
    <div className="flex flex-wrap gap-1.5">
      {techniques.map((t) => {
        const sev = severityConfig[t.severity] ?? severityConfig.info;
        const successRate =
          t.attempts > 0 ? Math.round((t.successes / t.attempts) * 100) : 0;
        const isSelected = selectedId === t.id;

        return (
          <div
            key={t.id}
            role="button"
            tabIndex={0}
            onClick={() => onSelect(t)}
            onKeyDown={(e) => e.key === "Enter" && onSelect(t)}
            title={`${t.id}: ${t.name}\nAttempts: ${t.attempts} | Successes: ${t.successes} | Success rate: ${successRate}%`}
            className={cn(
              "relative w-14 h-8 rounded border-2 cursor-pointer transition-all duration-150",
              "flex items-center justify-center",
              cellSuccessBorder(t.successes, t.attempts),
              cellIntensity(t.attempts, maxAttempts),
              sev.rowBg.split(" ")[0], // just the bg without hover
              isSelected && "ring-2 ring-primary ring-offset-1 ring-offset-background opacity-100",
              "hover:opacity-100 hover:scale-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            )}
          >
            <span className="text-[9px] font-mono text-foreground/80 leading-none px-0.5 text-center">
              {t.id}
            </span>
            {/* Success rate dot */}
            {t.successes > 0 && (
              <span
                className={cn(
                  "absolute top-0.5 right-0.5 w-1.5 h-1.5 rounded-full",
                  sev.dotClass
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// -----------------------------------------------------------------------
// Expandable detail row inside the table
// -----------------------------------------------------------------------

interface DetailRowProps {
  technique: MitreTechnique;
  colSpan: number;
}

function DetailRow({ technique, colSpan }: DetailRowProps) {
  return (
    <tr>
      <td colSpan={colSpan} className="bg-card/80 px-5 py-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Remediation */}
          <div className="md:col-span-1">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/70 mb-1.5">
              Remediation
            </p>
            <p className="text-xs text-zinc-300 leading-relaxed">
              {technique.remediation || "No remediation provided."}
            </p>
          </div>

          {/* Attack details */}
          <div className="md:col-span-1">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/70 mb-1.5">
              Attack Details
            </p>
            <p className="text-xs text-zinc-300 leading-relaxed">
              {technique.attackDetails || "No additional details."}
            </p>
          </div>

          {/* Affected targets */}
          <div className="md:col-span-1">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/70 mb-1.5">
              Affected Targets
            </p>
            {technique.affectedTargets && technique.affectedTargets.length > 0 ? (
              <ul className="space-y-0.5">
                {technique.affectedTargets.map((ip) => (
                  <li key={ip} className="text-xs font-mono text-zinc-300">
                    {ip}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted-foreground/60">None recorded.</p>
            )}
          </div>
        </div>
      </td>
    </tr>
  );
}

// -----------------------------------------------------------------------
// Main table
// -----------------------------------------------------------------------

interface HeatmapGridProps {
  techniques: MitreTechnique[];
  filterSeverity: string;
  sortKey: "severity" | "attempts" | "successRate";
}

const SEVERITY_ORDER: MitreSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function HeatmapGrid({
  techniques,
  filterSeverity,
  sortKey,
}: HeatmapGridProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = techniques
    .filter((t) => filterSeverity === "all" || t.severity === filterSeverity)
    .sort((a, b) => {
      if (sortKey === "severity") {
        const aIdx = SEVERITY_ORDER.indexOf(a.severity);
        const bIdx = SEVERITY_ORDER.indexOf(b.severity);
        if (aIdx !== bIdx) return aIdx - bIdx;
        return b.attempts - a.attempts;
      }
      if (sortKey === "attempts") return b.attempts - a.attempts;
      // successRate
      const aRate = a.attempts > 0 ? a.successes / a.attempts : 0;
      const bRate = b.attempts > 0 ? b.successes / b.attempts : 0;
      return bRate - aRate;
    });

  const COL_COUNT = 7;

  if (filtered.length === 0) {
    return (
      <div className="text-center py-10 text-sm text-muted-foreground">
        No techniques match the current filter.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border bg-secondary/30">
            <th className="text-left px-4 py-2.5 font-semibold tracking-wide text-muted-foreground w-28">
              Technique ID
            </th>
            <th className="text-left px-4 py-2.5 font-semibold tracking-wide text-muted-foreground">
              Name
            </th>
            <th className="text-right px-4 py-2.5 font-semibold tracking-wide text-muted-foreground w-20">
              Attempts
            </th>
            <th className="text-right px-4 py-2.5 font-semibold tracking-wide text-muted-foreground w-20">
              Successes
            </th>
            <th className="text-right px-4 py-2.5 font-semibold tracking-wide text-muted-foreground w-16">
              Blocks
            </th>
            <th className="text-right px-4 py-2.5 font-semibold tracking-wide text-muted-foreground w-20">
              Success %
            </th>
            <th className="text-center px-4 py-2.5 font-semibold tracking-wide text-muted-foreground w-24">
              Severity
            </th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((t) => {
            const sev = severityConfig[t.severity] ?? severityConfig.info;
            const successRate =
              t.attempts > 0
                ? Math.round((t.successes / t.attempts) * 100)
                : 0;
            const isExpanded = expandedId === t.id;

            return (
              <Fragment key={t.id}>
                <tr
                  onClick={() =>
                    setExpandedId((prev) => (prev === t.id ? null : t.id))
                  }
                  className={cn(
                    "border-b border-border/50 cursor-pointer transition-colors",
                    sev.rowBg
                  )}
                >
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground/40">
                        {isExpanded ? (
                          <ChevronDown className="w-3 h-3" />
                        ) : (
                          <ChevronRight className="w-3 h-3" />
                        )}
                      </span>
                      <span className="font-mono font-medium text-foreground">
                        {t.id}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-foreground/90">{t.name}</td>
                  <td className="px-4 py-2.5 text-right tabular-nums text-muted-foreground">
                    {t.attempts}
                  </td>
                  <td className="px-4 py-2.5 text-right tabular-nums">
                    <span
                      className={
                        t.successes > 0
                          ? "text-emerald-400"
                          : "text-muted-foreground"
                      }
                    >
                      {t.successes}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-right tabular-nums">
                    <span
                      className={
                        t.blocks > 0 ? "text-blue-400" : "text-muted-foreground"
                      }
                    >
                      {t.blocks}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-right tabular-nums">
                    <span
                      className={cn(
                        "font-mono",
                        successRate >= 50
                          ? "text-emerald-400"
                          : successRate >= 25
                            ? "text-yellow-400"
                            : "text-red-400/70"
                      )}
                    >
                      {successRate}%
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-center">
                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[10px] px-1.5 py-0",
                        sev.badgeClass
                      )}
                    >
                      {sev.label}
                    </Badge>
                  </td>
                </tr>

                {isExpanded && (
                  <DetailRow
                    key={`${t.id}-detail`}
                    technique={t}
                    colSpan={COL_COUNT}
                  />
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
