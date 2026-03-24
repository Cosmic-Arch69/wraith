
import { memo } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type EdgeProps,
} from "@xyflow/react";

// -----------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------

export interface OntologyEdgeData extends Record<string, unknown> {
  relationship?: string;
  label?: string;
  showLabel?: boolean;
}

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------

const DASHED_RELATIONSHIPS = new Set(["AUTHENTICATES_TO", "FORWARDS_TO"]);

const EDGE_COLOR = "#94a3b8";
const EDGE_COLOR_HOVER = "#64748b";

// -----------------------------------------------------------------------
// Component
// -----------------------------------------------------------------------

function OntologyEdgeComponent({
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
  const edgeData = data as OntologyEdgeData | undefined;
  const relationship = edgeData?.relationship ?? edgeData?.label ?? "";
  const showLabel = edgeData?.showLabel !== false;

  const isDashed = DASHED_RELATIONSHIPS.has(relationship);
  const strokeColor = selected ? EDGE_COLOR_HOVER : EDGE_COLOR;

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
          stroke: strokeColor,
          strokeWidth: selected ? 2 : 1.5,
          strokeDasharray: isDashed ? "5 4" : undefined,
          opacity: selected ? 1 : 0.65,
          transition: "stroke 0.15s, stroke-width 0.15s, opacity 0.15s",
        }}
      />

      {showLabel && relationship && (
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
              className={
                "text-[9px] font-mono px-1 py-0.5 rounded whitespace-nowrap " +
                "bg-white/90 border border-zinc-200 text-zinc-500 " +
                (selected ? "font-semibold border-zinc-400 text-zinc-700" : "")
              }
              style={{ lineHeight: "1.2" }}
            >
              {relationship}
            </span>
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export const OntologyEdge = memo(OntologyEdgeComponent);
