// Ontology Knowledge Graph Canvas -- D3 force-directed (MiroFish architecture)
// Uses D3 force simulation directly on SVG, NOT React Flow.
// This matches MiroFish's GraphPanel.vue exactly: forceLink + forceManyBody + forceCenter + forceCollide

import { useEffect, useRef, useState, useMemo } from 'react'
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  forceX,
  forceY,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from 'd3-force'
import { select } from 'd3-selection'
import { zoom, zoomIdentity } from 'd3-zoom'
import { drag as d3Drag } from 'd3-drag'
import {
  type OntologyNode as OntologyNodeModel,
  type OntologyEdge as OntologyEdgeModel,
  type EntityType,
} from '@/lib/ontology-graph'

// ---- Types ----

interface D3Node extends SimulationNodeDatum {
  id: string
  label: string
  entityType: EntityType
  significance?: string
}

interface D3Link extends SimulationLinkDatum<D3Node> {
  id: string
  relationship: string
  label: string
}

interface Props {
  nodes: OntologyNodeModel[]
  edges: OntologyEdgeModel[]
  showEdgeLabels?: boolean
}

// ---- MiroFish color palette ----
const MIROFISH_PALETTE: Record<EntityType, string> = {
  Host: '#FF6B35',
  Service: '#004E89',
  WebApplication: '#7B2D8E',
  Vulnerability: '#C5283D',
  Credential: '#f39c12',
  DomainController: '#E9724C',
  Domain: '#1A936F',
  PortForward: '#3498db',
  DiscoveredFile: '#9b59b6',
  User: '#27ae60',
}

const ALL_ENTITY_TYPES: EntityType[] = [
  'Host', 'Service', 'WebApplication', 'Vulnerability', 'Credential',
  'DomainController', 'Domain', 'PortForward', 'DiscoveredFile', 'User',
]

// ---- Component ----

export function OntologyGraphCanvas({ nodes, edges, showEdgeLabels = true }: Props): React.JSX.Element {
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ width: 1200, height: 800 })

  // Track present entity types for legend
  const presentTypes = useMemo(() => {
    const types = new Set<EntityType>()
    nodes.forEach((n) => types.add(n.entityType))
    return types
  }, [nodes])

  // Resize observer
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect
      if (width > 0 && height > 0) setDimensions({ width, height })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // D3 force simulation
  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return

    const { width, height } = dimensions
    const svg = select(svgRef.current)

    // Clear previous
    svg.selectAll('*').remove()

    // Container group for zoom/pan
    const g = svg.append('g')

    // Zoom behavior (MiroFish: D3 zoom)
    const zoomBehavior = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform)
      })
    svg.call(zoomBehavior)
    svg.call(zoomBehavior.transform, zoomIdentity.translate(width / 2, height / 2).scale(0.7))

    // Prepare D3 data
    const d3Nodes: D3Node[] = nodes.map((n) => ({
      id: n.id,
      label: n.label,
      entityType: n.entityType,
      significance: n.significance,
    }))

    const nodeMap = new Map(d3Nodes.map((n) => [n.id, n]))

    const d3Links: D3Link[] = edges
      .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        relationship: e.relationship,
        label: e.label,
      }))

    // Count edges per node for dynamic link distance
    const edgeCount = new Map<string, number>()
    d3Links.forEach((l) => {
      const sid = typeof l.source === 'string' ? l.source : (l.source as D3Node).id
      const tid = typeof l.target === 'string' ? l.target : (l.target as D3Node).id
      edgeCount.set(sid, (edgeCount.get(sid) || 0) + 1)
      edgeCount.set(tid, (edgeCount.get(tid) || 0) + 1)
    })

    // Force simulation (MiroFish params: forceManyBody -400, forceCollide 50)
    const simulation = forceSimulation(d3Nodes)
      .force(
        'link',
        forceLink<D3Node, D3Link>(d3Links)
          .id((d) => d.id)
          .distance((d) => {
            const sid = typeof d.source === 'string' ? d.source : (d.source as D3Node).id
            const tid = typeof d.target === 'string' ? d.target : (d.target as D3Node).id
            const sc = edgeCount.get(sid) || 1
            const tc = edgeCount.get(tid) || 1
            return 80 + Math.max(sc, tc) * 15
          })
      )
      .force('charge', forceManyBody().strength(-400))
      .force('center', forceCenter(0, 0))
      .force('collide', forceCollide(50))
      .force('x', forceX(0).strength(0.04))
      .force('y', forceY(0).strength(0.04))

    // Draw edges
    const linkGroup = g.append('g').attr('class', 'links')
    const linkElements = linkGroup
      .selectAll('line')
      .data(d3Links)
      .enter()
      .append('line')
      .attr('stroke', '#C0C0C0')
      .attr('stroke-width', 1.2)
      .attr('stroke-dasharray', (d) =>
        d.relationship === 'AUTHENTICATES_TO' || d.relationship === 'FORWARDS_TO' ? '5 3' : 'none'
      )
      .attr('marker-end', 'url(#arrow)')

    // Arrow marker
    svg.append('defs').append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 18)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#C0C0C0')

    // Edge labels
    const labelGroup = g.append('g').attr('class', 'edge-labels')
    const labelElements = labelGroup
      .selectAll('text')
      .data(d3Links)
      .enter()
      .append('text')
      .attr('font-size', '8px')
      .attr('font-family', 'monospace')
      .attr('fill', '#888')
      .attr('text-anchor', 'middle')
      .attr('dy', -4)
      .attr('visibility', showEdgeLabels ? 'visible' : 'hidden')
      .text((d) => d.relationship)

    // Draw nodes
    const nodeGroup = g.append('g').attr('class', 'nodes')
    const nodeElements = nodeGroup
      .selectAll('g')
      .data(d3Nodes)
      .enter()
      .append('g')
      .attr('cursor', 'pointer')

    // Node circle (MiroFish: radius 10)
    nodeElements
      .append('circle')
      .attr('r', 10)
      .attr('fill', (d) => MIROFISH_PALETTE[d.entityType] || '#888')
      .attr('stroke', '#0c0f1a')
      .attr('stroke-width', 2.5)

    // Node label
    nodeElements
      .append('text')
      .attr('dx', 14)
      .attr('dy', 4)
      .attr('font-size', '11px')
      .attr('font-family', 'system-ui, sans-serif')
      .attr('font-weight', '500')
      .attr('fill', '#c8cdd8')
      .text((d) => d.label.length > 22 ? d.label.slice(0, 22) + '...' : d.label)

    // Drag behavior (MiroFish: drag to fix position)
    const dragBehavior = d3Drag<SVGGElement, D3Node>()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart()
        d.fx = d.x
        d.fy = d.y
      })
      .on('drag', (event, d) => {
        d.fx = event.x
        d.fy = event.y
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0)
        d.fx = null
        d.fy = null
      })

    nodeElements.call(dragBehavior)

    // Tooltip on hover
    nodeElements
      .append('title')
      .text((d) => `${d.label}\nType: ${d.entityType}${d.significance ? '\n' + d.significance : ''}`)

    // Tick: update positions
    simulation.on('tick', () => {
      linkElements
        .attr('x1', (d) => (d.source as D3Node).x || 0)
        .attr('y1', (d) => (d.source as D3Node).y || 0)
        .attr('x2', (d) => (d.target as D3Node).x || 0)
        .attr('y2', (d) => (d.target as D3Node).y || 0)

      labelElements
        .attr('x', (d) => (((d.source as D3Node).x || 0) + ((d.target as D3Node).x || 0)) / 2)
        .attr('y', (d) => (((d.source as D3Node).y || 0) + ((d.target as D3Node).y || 0)) / 2)

      nodeElements.attr('transform', (d) => `translate(${d.x || 0},${d.y || 0})`)
    })

    // Cleanup
    return () => {
      simulation.stop()
    }
  }, [nodes, edges, dimensions, showEdgeLabels])

  if (nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-400">
        <svg className="w-10 h-10 mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
            d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19 14.5M14.25 3.104c.251.023.501.05.75.082M19 14.5l-2.47-2.47" />
        </svg>
        <p className="text-sm">No ontology data</p>
      </div>
    )
  }

  return (
    <div ref={containerRef} className="relative w-full h-full">
      <svg
        ref={svgRef}
        width={dimensions.width}
        height={dimensions.height}
        style={{ backgroundColor: '#0c0f1a' }}
      />

      {/* Entity Legend (bottom-left) */}
      <div className="absolute bottom-4 left-4 bg-card/95 border border-border rounded-lg px-3 py-2 shadow-sm">
        <p className="text-[9px] font-semibold tracking-widest text-zinc-400 uppercase mb-1.5">
          Entity Types
        </p>
        <div className="grid grid-cols-2 gap-x-3 gap-y-1">
          {ALL_ENTITY_TYPES.filter((t) => presentTypes.has(t)).map((type) => (
            <div key={type} className="flex items-center gap-1.5">
              <div
                className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{ background: MIROFISH_PALETTE[type] }}
              />
              <span className="text-[10px] text-zinc-600">{type}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Stats (top-left) */}
      <div className="absolute top-4 left-4 flex gap-2">
        <span className="text-[10px] font-mono bg-card/95 border border-border rounded px-2 py-0.5 text-muted-foreground">
          {nodes.length} entities
        </span>
        <span className="text-[10px] font-mono bg-card/95 border border-border rounded px-2 py-0.5 text-muted-foreground">
          {edges.length} relationships
        </span>
      </div>
    </div>
  )
}
