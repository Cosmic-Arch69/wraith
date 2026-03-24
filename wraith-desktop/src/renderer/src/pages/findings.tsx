
import { useEffect, useState, useCallback } from "react";
import { AlertTriangle } from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import { FindingTableRow } from "@/components/findings/finding-row";
import { getFindingRows } from "@/lib/api-extended";
import type { FindingRow, FindingSeverity } from "@/lib/api-extended";
import { cn } from "@/lib/utils";

const SEVERITY_ORDER: FindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const SEVERITY_COLORS: Record<FindingSeverity, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-zinc-400",
};

type ScopeFilter = "all" | FindingSeverity;

export default function FindingsPage() {
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ScopeFilter>("all");

  const load = useCallback(async () => {
    try {
      const raw = await getFindingRows();
      // Normalize severity to lowercase (API may return "Critical" vs "critical")
      const data = raw.map((f) => ({
        ...f,
        severity: f.severity.toLowerCase() as FindingSeverity,
      }));
      // Sort by severity order then by title
      const sorted = [...data].sort((a, b) => {
        const ai = SEVERITY_ORDER.indexOf(a.severity);
        const bi = SEVERITY_ORDER.indexOf(b.severity);
        if (ai !== bi) return ai - bi;
        return a.title.localeCompare(b.title);
      });
      setFindings(sorted);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const counts = SEVERITY_ORDER.reduce<Record<FindingSeverity, number>>(
    (acc, s) => {
      acc[s] = findings.filter((f) => f.severity === s).length;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  const filtered =
    filter === "all" ? findings : findings.filter((f) => f.severity === filter);

  // Group filtered findings by severity for the severity-grouped table
  const grouped = SEVERITY_ORDER.reduce<Record<FindingSeverity, FindingRow[]>>(
    (acc, s) => {
      acc[s] = filtered.filter((f) => f.severity === s);
      return acc;
    },
    { critical: [], high: [], medium: [], low: [], info: [] }
  );

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <AlertTriangle className="w-5 h-5 text-primary" />
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-foreground">
            Findings
          </h1>
          <p className="text-sm text-muted-foreground">
            Vulnerabilities and security findings with severity ratings
          </p>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(["critical", "high", "medium", "low"] as FindingSeverity[]).map(
          (sev) => (
            <div
              key={sev}
              className="rounded-lg border border-border bg-card p-4 flex flex-col gap-1"
            >
              <span
                className={cn(
                  "text-xs font-semibold uppercase tracking-widest",
                  SEVERITY_COLORS[sev]
                )}
              >
                {sev}
              </span>
              <span className="text-2xl font-bold font-mono text-foreground">
                {loading ? "--" : counts[sev]}
              </span>
            </div>
          )
        )}
      </div>

      {/* Severity filter tabs */}
      <Tabs
        value={filter}
        onValueChange={(v) => setFilter(v as ScopeFilter)}
      >
        <TabsList>
          <TabsTrigger value="all">All ({findings.length})</TabsTrigger>
          {SEVERITY_ORDER.map((s) => (
            <TabsTrigger key={s} value={s}>
              <span className={cn("capitalize", SEVERITY_COLORS[s])}>{s}</span>
              {counts[s] > 0 && (
                <span className="ml-1 text-muted-foreground">({counts[s]})</span>
              )}
            </TabsTrigger>
          ))}
        </TabsList>

        {(["all", ...SEVERITY_ORDER] as ScopeFilter[]).map((tab) => (
          <TabsContent key={tab} value={tab}>
            {loading ? (
              <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
                Loading findings...
              </div>
            ) : error ? (
              <div className="rounded-lg border border-destructive/30 bg-card p-6 text-center text-sm text-destructive">
                {error}
              </div>
            ) : filtered.length === 0 ? (
              <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
                <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-muted-foreground/40" />
                <p>No findings for this severity level.</p>
              </div>
            ) : (
              <div className="rounded-lg border border-border bg-card overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b border-border hover:bg-transparent">
                      <TableHead className="w-8" />
                      <TableHead className="font-medium text-foreground w-28">
                        Severity
                      </TableHead>
                      <TableHead className="font-medium text-foreground">
                        Finding
                      </TableHead>
                      <TableHead className="font-medium text-foreground w-24">
                        Attempts / Hits
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {SEVERITY_ORDER.map((sev) => {
                      const group = grouped[sev];
                      if (group.length === 0) return null;

                      return group.map((finding, i) => (
                        <FindingTableRow key={finding.id ?? `${sev}-${i}`} finding={finding} />
                      ));
                    })}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
