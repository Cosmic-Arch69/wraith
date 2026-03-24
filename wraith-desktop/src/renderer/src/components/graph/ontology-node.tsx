import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { ENTITY_COLORS, type EntityType } from "@/lib/ontology-graph";

// -----------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------

export interface OntologyNodeData extends Record<string, unknown> {
  label: string;
  entityType: EntityType;
  significance?: string;
}

// -----------------------------------------------------------------------
// MiroFish-style: colored circle + text label
// -----------------------------------------------------------------------

function OntologyNodeComponent({ data, selected }: NodeProps) {
  const nodeData = data as OntologyNodeData;
  const { label, entityType } = nodeData;

  const color = ENTITY_COLORS[entityType] ?? "#94a3b8";
  const truncated =
    label && label.length > 18 ? `${label.slice(0, 18)}...` : label;

  return (
    <div
      className="relative flex items-center gap-1.5"
      style={{ cursor: "pointer" }}
    >
      {/* Colored circle (MiroFish: 10px radius = 20px diameter) */}
      <div
        style={{
          width: 20,
          height: 20,
          borderRadius: "50%",
          backgroundColor: color,
          border: selected ? "3px solid white" : "2px solid white",
          boxShadow: selected
            ? `0 0 0 2px ${color}, 0 2px 6px rgba(0,0,0,0.2)`
            : "0 1px 3px rgba(0,0,0,0.15)",
          flexShrink: 0,
        }}
      />

      {/* Text label beside the circle */}
      <span
        className="text-[11px] font-medium text-zinc-700 whitespace-nowrap select-none"
        style={{
          textShadow: "0 0 3px white, 0 0 3px white, 0 0 3px white",
          fontWeight: selected ? 700 : 500,
        }}
        title={`${label} (${entityType})`}
      >
        {truncated}
      </span>

      {/* Invisible handles for React Flow edges */}
      <Handle
        type="target"
        position={Position.Left}
        style={{ width: 1, height: 1, opacity: 0, left: 10 }}
      />
      <Handle
        type="source"
        position={Position.Right}
        style={{ width: 1, height: 1, opacity: 0, right: -2 }}
      />
    </div>
  );
}

export const OntologyNode = memo(OntologyNodeComponent);
