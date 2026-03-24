
import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import {
  Monitor,
  Server,
  Shield,
  Terminal,
  Database,
  Globe,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { AccessLevel, NodeType } from "@/lib/types";

// -----------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------

export interface HostNodeData extends Record<string, unknown> {
  label: string;
  ip?: string;
  type: NodeType;
  accessLevel: AccessLevel;
  services?: string[];
  tags?: string[];
  isBlocked?: boolean;
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function getNodeIcon(type: NodeType, label: string) {
  const lower = label.toLowerCase();
  if (lower.includes("kali") || type === "kali") return Terminal;
  if (
    lower.includes("dc") ||
    lower.includes("domain") ||
    type === "domain_controller"
  )
    return Server;
  if (lower.includes("pfsense") || lower.includes("firewall")) return Shield;
  if (type === "database") return Database;
  if (type === "web") return Globe;
  return Monitor;
}

const accessBorderColors: Record<AccessLevel, string> = {
  none: "border-zinc-600",
  discovered: "border-zinc-500",
  credentials: "border-yellow-600",
  user: "border-blue-500",
  admin: "border-amber-500",
  system: "border-red-500",
  domain_admin: "border-orange-500",
  domain_controller: "border-red-500",
};

const accessBadgeColors: Record<AccessLevel, string> = {
  none: "bg-zinc-700 text-zinc-300",
  discovered: "bg-zinc-600 text-zinc-200",
  credentials: "bg-yellow-900/60 text-yellow-300",
  user: "bg-blue-900/60 text-blue-300",
  admin: "bg-amber-900/60 text-amber-300",
  system: "bg-red-900/60 text-red-300",
  domain_admin: "bg-orange-900/60 text-orange-300",
  domain_controller: "bg-red-900/60 text-red-300",
};

const accessLabel: Record<AccessLevel, string> = {
  none: "none",
  discovered: "disc",
  credentials: "creds",
  user: "user",
  admin: "admin",
  system: "SYSTEM",
  domain_admin: "DA",
  domain_controller: "DC",
};

// -----------------------------------------------------------------------
// Component
// -----------------------------------------------------------------------

function HostNodeComponent({ data, selected }: NodeProps) {
  const nodeData = data as HostNodeData;
  const {
    label,
    ip,
    type,
    accessLevel,
    services,
    isBlocked,
  } = nodeData;

  const Icon = getNodeIcon(type ?? "host", label ?? "");
  const borderClass = accessBorderColors[accessLevel ?? "none"];
  const badgeClass = accessBadgeColors[accessLevel ?? "none"];

  return (
    <div
      className={cn(
        "relative w-[180px] rounded-lg border-2 bg-zinc-900 px-3 py-2.5 shadow-lg transition-all",
        borderClass,
        selected && "ring-2 ring-white/20 ring-offset-1 ring-offset-zinc-950",
        isBlocked && "opacity-80"
      )}
    >
      {/* Blocked overlay badge */}
      {isBlocked && (
        <div className="absolute -top-2 -right-2 z-10 flex items-center justify-center w-5 h-5 rounded-full bg-red-600 border border-red-500">
          <Shield className="w-3 h-3 text-white" />
        </div>
      )}

      {/* Top row: icon + hostname */}
      <div className="flex items-center gap-2 mb-1.5">
        <div
          className={cn(
            "flex items-center justify-center w-6 h-6 rounded shrink-0",
            type === "kali" || label?.toLowerCase().includes("kali")
              ? "bg-red-900/40 text-red-400"
              : "bg-zinc-800 text-zinc-300"
          )}
        >
          <Icon className="w-3.5 h-3.5" />
        </div>
        <span
          className="text-xs font-mono font-semibold text-zinc-100 truncate leading-none"
          title={label}
        >
          {label}
        </span>
      </div>

      {/* IP */}
      {ip && (
        <div className="text-[10px] font-mono text-zinc-400 mb-1.5 pl-0.5">
          {ip}
        </div>
      )}

      {/* Bottom row: services badge + access badge */}
      <div className="flex items-center justify-between gap-1">
        {services && services.length > 0 ? (
          <span className="text-[9px] font-mono bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded">
            {services.length} svc{services.length !== 1 ? "s" : ""}
          </span>
        ) : (
          <span />
        )}
        <span
          className={cn(
            "text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded",
            badgeClass
          )}
        >
          {accessLabel[accessLevel ?? "none"]}
        </span>
      </div>

      {/* React Flow handles */}
      <Handle
        type="target"
        position={Position.Left}
        className="!w-2 !h-2 !bg-zinc-600 !border-zinc-500"
      />
      <Handle
        type="source"
        position={Position.Right}
        className="!w-2 !h-2 !bg-zinc-600 !border-zinc-500"
      />
    </div>
  );
}

export const HostNode = memo(HostNodeComponent);
