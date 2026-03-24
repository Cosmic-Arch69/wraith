
import { memo } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type Edge,
  type EdgeProps,
} from "@xyflow/react";
import type { EdgeType } from "@/lib/types";

// -----------------------------------------------------------------------
// Types -- data must satisfy Record<string, unknown> for @xyflow/react
// -----------------------------------------------------------------------

export interface AttackEdgeData extends Record<string, unknown> {
  label?: string;
  via?: string;
  edgeType?: EdgeType;
  roundId?: number;
}

export type AttackEdgeType = Edge<AttackEdgeData>;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

const edgeColors: Record<EdgeType | "default", string> = {
  network: "#52525b",
  exploit: "#ef4444",
  lateral: "#f59e0b",
  credential: "#3b82f6",
  trust: "#8b5cf6",
  default: "#52525b",
};

// -----------------------------------------------------------------------
// Component
// -----------------------------------------------------------------------

function AttackEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
  markerEnd,
}: EdgeProps) {
  const edgeData = data as AttackEdgeData | undefined;
  const edgeType: EdgeType = (edgeData?.edgeType as EdgeType) ?? "network";
  const color = edgeColors[edgeType] ?? edgeColors.default;
  const via = edgeData?.via as string | undefined;

  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          stroke: color,
          strokeWidth: selected ? 2.5 : 1.5,
          strokeDasharray:
            edgeType === "lateral" || edgeType === "credential"
              ? "6 3"
              : undefined,
          opacity: selected ? 1 : 0.7,
        }}
      />

      {/* Animated flow dashes for exploit/lateral edges */}
      {(edgeType === "exploit" || edgeType === "lateral") && (
        <path
          d={edgePath}
          fill="none"
          stroke={color}
          strokeWidth={1.5}
          strokeDasharray="8 12"
          strokeOpacity={0.5}
          style={{ animation: "dash 1.5s linear infinite" }}
        />
      )}

      {/* Via label */}
      {via && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: "all",
            }}
            className="nodrag nopan"
          >
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-zinc-950/90 border border-zinc-700 whitespace-nowrap"
              style={{ color }}
            >
              {via}
            </span>
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export const AttackEdge = memo(AttackEdgeComponent);
