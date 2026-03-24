
import { useEffect, useCallback, useRef } from "react";
import { GitBranch, RefreshCw, Wifi, WifiOff } from "lucide-react";
import { AttackGraphCanvas } from "@/components/graph/attack-graph-canvas";
import { useEngagementStore } from "@/stores/engagement-store";
import { getGraph } from "@/lib/api";
import { cn } from "@/lib/utils";

// -----------------------------------------------------------------------
// Graph page -- full React Flow attack graph
// -----------------------------------------------------------------------

export default function GraphPage() {
  const graph = useEngagementStore((s) => s.graph);
  const setGraph = useEngagementStore((s) => s.setGraph);
  const sseConnected = useEngagementStore((s) => s.sseConnected);

  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // -----------------------------------------------------------------------
  // Fetch graph snapshot
  // -----------------------------------------------------------------------

  const fetchGraph = useCallback(async () => {
    try {
      const data = await getGraph();
      setGraph(data);
    } catch {
      // Backend not running -- ignore silently
    }
  }, [setGraph]);

  // -----------------------------------------------------------------------
  // SSE connection for live updates
  // -----------------------------------------------------------------------

  // SSE handled globally by App.tsx SseBridge -- no separate connection here
  // Graph updates come through the global engagement store

  // -----------------------------------------------------------------------
  // Polling fallback (every 5s)
  // -----------------------------------------------------------------------

  // Fetch once on mount. Only poll during active pipeline runs.
  useEffect(() => {
    fetchGraph();
    // Don't poll in replay mode -- data is static
    // Polling only needed when pipeline is running (SSE will handle live updates)
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [fetchGraph]);

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  const nodeCount = graph?.nodes.length ?? 0;
  const edgeCount = graph?.edges.length ?? 0;

  return (
    <div className="flex flex-col gap-0 h-full">
      {/* Header bar */}
      <div className="flex items-center gap-3 pb-4 shrink-0">
        <GitBranch className="w-5 h-5 text-primary" />
        <div className="flex-1 min-w-0">
          <h1 className="text-lg font-semibold tracking-tight text-foreground">
            Attack Graph
          </h1>
          <p className="text-sm text-muted-foreground">
            Interactive node graph of discovered hosts and attack paths
          </p>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-4 text-xs text-muted-foreground font-mono">
          <span>
            <span className="text-foreground font-semibold">{nodeCount}</span>{" "}
            nodes
          </span>
          <span>
            <span className="text-foreground font-semibold">{edgeCount}</span>{" "}
            edges
          </span>
        </div>

        {/* Connection status */}
        <div className="flex items-center gap-2">
          {sseConnected ? (
            <>
              <Wifi className="w-3.5 h-3.5 text-emerald-500" />
              <span className="text-[11px] text-emerald-400">live</span>
            </>
          ) : (
            <>
              <WifiOff className="w-3.5 h-3.5 text-zinc-600" />
              <span className="text-[11px] text-zinc-500">polling</span>
            </>
          )}
        </div>

        {/* Manual refresh */}
        <button
          onClick={fetchGraph}
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded border border-border hover:bg-secondary"
          title="Refresh graph"
        >
          <RefreshCw className="w-3 h-3" />
          Refresh
        </button>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 pb-3 shrink-0 flex-wrap">
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground/60 font-semibold">
          Access
        </span>
        {[
          { color: "bg-zinc-600", label: "None" },
          { color: "bg-blue-500", label: "User" },
          { color: "bg-amber-500", label: "Admin" },
          { color: "bg-orange-500", label: "Domain Admin" },
          { color: "bg-red-500", label: "DC" },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className={cn("w-2.5 h-2.5 rounded-sm border", color)} />
            <span className="text-[10px] text-muted-foreground">{label}</span>
          </div>
        ))}
        <div className="ml-4 w-px h-3 bg-border" />
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground/60 font-semibold">
          Edge
        </span>
        {[
          { color: "bg-zinc-600", label: "Network" },
          { color: "bg-red-500", label: "Exploit" },
          { color: "bg-amber-500", label: "Lateral" },
          { color: "bg-blue-500", label: "Credential" },
          { color: "bg-violet-500", label: "Trust" },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className={cn("w-4 h-0.5", color)} />
            <span className="text-[10px] text-muted-foreground">{label}</span>
          </div>
        ))}
      </div>

      {/* Canvas */}
      <div className="flex-1 rounded-lg border border-border overflow-hidden min-h-0">
        <AttackGraphCanvas graph={graph} />
      </div>
    </div>
  );
}
