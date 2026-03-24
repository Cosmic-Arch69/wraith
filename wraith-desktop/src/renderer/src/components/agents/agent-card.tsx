
import { useState, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  ChevronDown,
  ChevronRight,
  Loader2,
  FileText,
  Key,
  Clock,
  Hash,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { AgentMeta, AgentStatus, AgentTemplate } from "@/lib/agent-types";

// -----------------------------------------------------------------------
// Colour maps
// -----------------------------------------------------------------------

const statusConfig: Record<
  AgentStatus,
  { label: string; className: string }
> = {
  success: {
    label: "SUCCESS",
    className:
      "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25",
  },
  failed: {
    label: "FAILED",
    className: "bg-red-500/10 text-red-400 border border-red-500/25",
  },
  timeout: {
    label: "TIMEOUT",
    className: "bg-yellow-500/10 text-yellow-400 border border-yellow-500/25",
  },
  refused: {
    label: "REFUSED",
    className:
      "bg-purple-500/10 text-purple-400 border border-purple-500/25",
  },
  no_findings: {
    label: "NO FINDINGS",
    className: "bg-zinc-700/30 text-zinc-400 border border-zinc-600/30",
  },
  running: {
    label: "RUNNING",
    className: "bg-blue-500/10 text-blue-400 border border-blue-500/25",
  },
};

const templateConfig: Record<
  AgentTemplate,
  { label: string; className: string }
> = {
  sqli: {
    label: "sqli",
    className: "bg-orange-500/10 text-orange-400 border border-orange-500/20",
  },
  lateral: {
    label: "lateral",
    className: "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20",
  },
  privesc: {
    label: "privesc",
    className: "bg-red-500/10 text-red-400 border border-red-500/20",
  },
  recon: {
    label: "recon",
    className: "bg-blue-500/10 text-blue-400 border border-blue-500/20",
  },
  exploit: {
    label: "exploit",
    className:
      "bg-purple-500/10 text-purple-400 border border-purple-500/20",
  },
  bruteforce: {
    label: "bruteforce",
    className: "bg-pink-500/10 text-pink-400 border border-pink-500/20",
  },
  exfil: {
    label: "exfil",
    className:
      "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20",
  },
  persistence: {
    label: "persist",
    className:
      "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20",
  },
  other: {
    label: "other",
    className: "bg-zinc-700/30 text-zinc-400 border border-zinc-600/30",
  },
};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}m ${rem}s`;
}

const BASE_URL =
  typeof window !== "undefined"
    ? ("http://localhost:3001")
    : "http://localhost:3001";

async function fetchAgentOutput(agentId: string): Promise<string> {
  const res = await fetch(
    `${BASE_URL}/api/agents/${encodeURIComponent(agentId)}/output`,
    { cache: "no-store" }
  );
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  // The endpoint may return plain markdown text or JSON
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const data = await res.json();
    // Accept { output: string } or { response: string } or just stringify
    if (typeof data === "string") return data;
    if (typeof data?.output === "string") return data.output;
    if (typeof data?.response === "string") return data.response;
    return JSON.stringify(data, null, 2);
  }
  return res.text();
}

// -----------------------------------------------------------------------
// Expanded output pane
// -----------------------------------------------------------------------

interface OutputPaneProps {
  agentId: string;
  evidenceFiles: string[];
}

function OutputPane({ agentId, evidenceFiles }: OutputPaneProps) {
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (markdown !== null || loading) return;
    setLoading(true);
    try {
      const text = await fetchAgentOutput(agentId);
      setMarkdown(text);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load output");
    } finally {
      setLoading(false);
    }
  }, [agentId, markdown, loading]);

  // Trigger load on mount
  useState(() => {
    load();
  });

  return (
    <div className="border-t border-border pt-3 mt-1 space-y-3">
      {/* Agent output */}
      <div>
        <p className="text-[10px] font-semibold tracking-widest uppercase text-muted-foreground/70 mb-2">
          Agent Output
        </p>
        {loading && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground py-4">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Loading output...
          </div>
        )}
        {error && (
          <div className="text-xs text-red-400 bg-red-500/5 border border-red-500/20 rounded px-3 py-2">
            {error}
          </div>
        )}
        {markdown !== null && !loading && (
          <ScrollArea className="max-h-80 rounded-md">
            <div
              className={cn(
                "text-xs font-mono leading-relaxed text-zinc-300",
                "bg-zinc-950/60 border border-border rounded-md p-3",
                "prose prose-invert prose-xs max-w-none",
                "[&_h1]:text-sm [&_h1]:font-semibold [&_h1]:text-foreground [&_h1]:mb-2",
                "[&_h2]:text-xs [&_h2]:font-semibold [&_h2]:text-foreground [&_h2]:mb-1",
                "[&_h3]:text-xs [&_h3]:font-semibold [&_h3]:text-muted-foreground [&_h3]:mb-1",
                "[&_p]:mb-2 [&_p]:text-zinc-300",
                "[&_code]:bg-zinc-800 [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-[11px]",
                "[&_pre]:bg-zinc-900 [&_pre]:border [&_pre]:border-border [&_pre]:rounded [&_pre]:p-2 [&_pre]:overflow-x-auto",
                "[&_ul]:list-disc [&_ul]:pl-4 [&_ul]:space-y-0.5",
                "[&_ol]:list-decimal [&_ol]:pl-4 [&_ol]:space-y-0.5",
                "[&_li]:text-zinc-300",
                "[&_strong]:text-foreground",
                "[&_a]:text-primary [&_a]:underline",
                "[&_blockquote]:border-l-2 [&_blockquote]:border-border [&_blockquote]:pl-3 [&_blockquote]:text-muted-foreground",
                "[&_table]:w-full [&_table]:text-xs",
                "[&_th]:text-left [&_th]:py-1 [&_th]:px-2 [&_th]:border-b [&_th]:border-border",
                "[&_td]:py-1 [&_td]:px-2 [&_td]:border-b [&_td]:border-border/50",
                "[&_hr]:border-border"
              )}
            >
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {markdown}
              </ReactMarkdown>
            </div>
          </ScrollArea>
        )}
      </div>

      {/* Evidence files */}
      {evidenceFiles.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold tracking-widest uppercase text-muted-foreground/70 mb-2">
            Evidence Files
          </p>
          <ul className="space-y-1">
            {evidenceFiles.map((file) => (
              <li
                key={file}
                className="flex items-center gap-2 text-xs text-zinc-400 font-mono"
              >
                <FileText className="w-3 h-3 text-muted-foreground shrink-0" />
                {file}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------
// Agent Card
// -----------------------------------------------------------------------

interface AgentCardProps {
  agent: AgentMeta;
}

export function AgentCard({ agent }: AgentCardProps) {
  const [expanded, setExpanded] = useState(false);

  const statusCfg = statusConfig[agent.status];
  const templateCfg = templateConfig[agent.template] ?? templateConfig.other;
  const isRunning = agent.status === "running";

  return (
    <div
      className={cn(
        "rounded-lg border bg-card transition-colors",
        agent.status === "success"
          ? "border-emerald-500/15"
          : agent.status === "failed"
            ? "border-red-500/15"
            : agent.status === "running"
              ? "border-blue-500/20"
              : "border-border"
      )}
    >
      {/* Card header -- always visible, clickable to expand */}
      <button
        type="button"
        onClick={() => !isRunning && setExpanded((v) => !v)}
        className={cn(
          "w-full text-left px-4 py-3 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50",
          !isRunning && "cursor-pointer"
        )}
        disabled={isRunning}
      >
        <div className="flex items-start gap-3">
          {/* Expand chevron */}
          <div className="mt-0.5 shrink-0 text-muted-foreground/50">
            {isRunning ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400" />
            ) : expanded ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" />
            )}
          </div>

          {/* Main content */}
          <div className="flex-1 min-w-0 space-y-2">
            {/* Row 1: agent ID + badges */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono font-semibold text-foreground truncate">
                {agent.agentId}
              </span>
              <Badge
                variant="outline"
                className={cn("text-[10px] px-1.5 py-0", templateCfg.className)}
              >
                {templateCfg.label}
              </Badge>
              <Badge
                variant="outline"
                className={cn("text-[10px] px-1.5 py-0", statusCfg.className)}
              >
                {isRunning ? (
                  <span className="flex items-center gap-1">
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                    {statusCfg.label}
                  </span>
                ) : (
                  statusCfg.label
                )}
              </Badge>
            </div>

            {/* Row 2: target IP + stats */}
            <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
              {/* Target */}
              <span className="flex items-center gap-1.5 font-mono">
                <Hash className="w-3 h-3" />
                {agent.target}
              </span>

              {/* Turns + duration */}
              <span className="flex items-center gap-1.5">
                <Clock className="w-3 h-3" />
                {isRunning ? (
                  <span className="text-blue-400/80">Running...</span>
                ) : (
                  <>
                    {agent.turns} turns,&nbsp;
                    <span className="tabular-nums">
                      {formatDuration(agent.durationMs)}
                    </span>
                  </>
                )}
              </span>

              {/* Credentials */}
              {agent.credentialsFound > 0 && (
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <Key className="w-3 h-3" />
                  {agent.credentialsFound} cred
                  {agent.credentialsFound !== 1 ? "s" : ""}
                </span>
              )}

              {/* Evidence count */}
              {agent.evidenceFiles.length > 0 && (
                <span className="flex items-center gap-1.5 text-zinc-500">
                  <FileText className="w-3 h-3" />
                  {agent.evidenceFiles.length} file
                  {agent.evidenceFiles.length !== 1 ? "s" : ""}
                </span>
              )}
            </div>
          </div>
        </div>
      </button>

      {/* Expanded section */}
      {expanded && !isRunning && (
        <div className="px-4 pb-4">
          <OutputPane
            agentId={agent.agentId}
            evidenceFiles={agent.evidenceFiles}
          />
        </div>
      )}
    </div>
  );
}
