
import { useState } from "react";
import { ChevronDown, ChevronRight, Shield } from "lucide-react";
import { TableRow, TableCell } from "@/components/ui/table";
import type { FindingRow } from "@/lib/api-extended";
import { cn } from "@/lib/utils";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

interface FindingRowProps {
  finding: FindingRow;
}

export function FindingTableRow({ finding }: FindingRowProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <TableRow
        className="border-b border-border/50 cursor-pointer hover:bg-muted/40 transition-colors"
        onClick={() => setExpanded((v) => !v)}
      >
        <TableCell className="w-8 text-muted-foreground">
          {expanded ? (
            <ChevronDown className="size-3.5" />
          ) : (
            <ChevronRight className="size-3.5" />
          )}
        </TableCell>
        <TableCell>
          <span
            className={cn(
              "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide",
              SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.info
            )}
          >
            {finding.severity}
          </span>
        </TableCell>
        <TableCell>
          <div className="flex flex-col gap-0.5">
            <span className="font-medium text-sm text-foreground">
              {finding.title}
            </span>
            <span className="font-mono text-xs text-muted-foreground">
              {finding.technique}
              {finding.techniqueName ? ` -- ${finding.techniqueName}` : ""}
            </span>
          </div>
        </TableCell>
        <TableCell>
          <div className="flex items-center gap-1.5 font-mono text-xs">
            <span className="text-muted-foreground">{finding.attempts}</span>
            <span className="text-muted-foreground/40">/</span>
            <span className="text-green-400">{finding.successes}</span>
          </div>
          <div className="text-xs text-muted-foreground/60 mt-0.5">
            att / hit
          </div>
        </TableCell>
      </TableRow>

      {expanded && (
        <TableRow className="border-b border-border/30 bg-muted/20">
          <TableCell colSpan={4} className="py-3 px-4">
            <div className="flex gap-2">
              <Shield className="size-4 text-primary shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">
                  Remediation
                </p>
                <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">
                  {finding.remediation || "No remediation guidance available."}
                </p>
              </div>
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
