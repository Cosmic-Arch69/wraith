// Attack Graph Canvas -- Cytoscape.js (Stormspotter/BloodHound architecture)
// Replaces React Flow with Cytoscape for proper security tool graph visualization
// Features: click-to-highlight paths, dagre layout, dark theme, drag persistence

import { useEffect, useRef, useCallback } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import coseBilkent from 'cytoscape-cose-bilkent'
import type { GraphData } from '@/lib/types'

// Register layout extensions
cytoscape.use(dagre)
cytoscape.use(coseBilkent)

// ---- SVG icons as data URLs (Stormspotter-style background-image on nodes) ----
function svgToDataUrl(svg: string): string {
  return `data:image/svg+xml,${encodeURIComponent(svg)}`
}

// SVG icons based on ACTUAL OS from nmap recon scan
const NODE_ICONS: Record<string, string> = {
  // Kali Linux terminal
  kali: svgToDataUrl(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`),
  // Windows Server (server rack)
  windows_server: svgToDataUrl(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`),
  // Windows workstation (monitor)
  windows: svgToDataUrl(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`),
  // pfSense / Firewall (shield)
  pfsense: svgToDataUrl(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`),
  // Linux (generic)
  linux: svgToDataUrl(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`),
}

// Pick icon based on OS string from nmap recon
function getNodeIcon(nodeType: string, os = ''): string {
  const osLower = (os || '').toLowerCase()
  if (nodeType === 'kali') return NODE_ICONS.kali
  if (osLower.includes('pfsense') || nodeType === 'firewall') return NODE_ICONS.pfsense
  if (osLower.includes('server')) return NODE_ICONS.windows_server
  if (osLower.includes('windows')) return NODE_ICONS.windows
  if (osLower.includes('linux') || osLower.includes('ubuntu') || osLower.includes('debian') || osLower.includes('kali')) return NODE_ICONS.linux
  if (nodeType === 'domain_controller') return NODE_ICONS.windows_server
  return NODE_ICONS.windows
}

function getNodeShape(type: string): string {
  switch (type) {
    case 'kali': return 'round-rectangle'
    case 'domain_controller': return 'diamond'
    case 'firewall': return 'round-hexagon'
    default: return 'round-rectangle'
  }
}

function getNodeColor(accessLevel: string): string {
  switch (accessLevel) {
    case 'system': return '#ef4444'
    case 'admin': return '#f59e0b'
    case 'user': return '#3b82f6'
    case 'discovered': return '#6b7280'
    case 'domain_controller': return '#e85d3a' // Kali attacker
    default: return '#374151'
  }
}

function getEdgeColor(type: string): string {
  switch (type) {
    case 'exploit': return '#ef4444'
    case 'lateral': return '#f59e0b'
    case 'credential': return '#3b82f6'
    default: return '#6b7280'
  }
}

// ---- Cytoscape style config (Stormspotter-inspired) ----
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CY_STYLE: any[] = [
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'color': '#e8eaf0',
      'font-size': 11,
      'font-family': 'ui-monospace, monospace',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 8,
      'text-background-color': '#0c0f1a',
      'text-background-opacity': 0.8,
      'text-background-padding': 3,
      'text-background-shape': 'roundrectangle',
      'background-color': 'data(color)',
      'background-image': 'data(icon)',
      'background-fit': 'contain',
      'background-clip': 'none',
      'background-width': '55%',
      'background-height': '55%',
      'border-width': 2,
      'border-color': 'data(borderColor)',
      'width': 50,
      'height': 50,
      'shape': 'data(shape)',
      'overlay-opacity': 0,
    },
  },
  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': 'data(color)',
      'target-arrow-color': 'data(color)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'label': 'data(label)',
      'color': '#8b92a8',
      'font-size': 9,
      'font-family': 'ui-monospace, monospace',
      'text-rotation': 'autorotate',
      'text-margin-y': -8,
      'text-background-color': '#0c0f1a',
      'text-background-opacity': 0.85,
      'text-background-padding': 2 as unknown as string,
      'text-background-shape': 'roundrectangle',
      'overlay-opacity': 0,
    },
  },
  // Selected node: bright border
  {
    selector: 'node:selected',
    style: {
      'border-width': 3,
      'border-color': '#ffffff',
      'color': '#e85d3a',
      'z-index': 999,
    },
  },
  // Stormspotter: outgoing paths (green)
  {
    selector: '.outgoing',
    style: {
      'line-color': '#4ade80',
      'target-arrow-color': '#4ade80',
      'color': '#4ade80',
      'z-index': 999,
    },
  },
  {
    selector: '.outgoing-node',
    style: {
      'border-color': '#4ade80',
      'border-width': 3,
      'color': '#4ade80',
      'z-index': 999,
    },
  },
  // Stormspotter: incoming paths (orange)
  {
    selector: '.incoming',
    style: {
      'line-color': '#fb923c',
      'target-arrow-color': '#fb923c',
      'color': '#fb923c',
      'z-index': 999,
    },
  },
  {
    selector: '.incoming-node',
    style: {
      'border-color': '#fb923c',
      'border-width': 3,
      'color': '#fb923c',
      'z-index': 999,
    },
  },
  // Stormspotter: dim unrelated nodes
  {
    selector: '.dimmed',
    style: {
      'opacity': 0.15,
    },
  },
]

// ---- Component ----

interface Props {
  graph: GraphData | null
  compact?: boolean
}

export function AttackGraphCanvas({ graph, compact = false }: Props): React.JSX.Element {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)

  const buildElements = useCallback((g: GraphData): cytoscape.ElementDefinition[] => {
    const elements: cytoscape.ElementDefinition[] = []

    for (const node of g.nodes) {
      // Clean label: just hostname (no long FQDN or IP duplication)
      const shortLabel = (node.label || '').split(' / ')[0].split('.')[0] || node.ip || node.id
      const os = (node as { os?: string }).os || ''

      elements.push({
        data: {
          id: node.id,
          label: shortLabel,
          color: getNodeColor(node.accessLevel),
          borderColor: node.tags?.includes('blocked') ? '#dc2626' : getNodeColor(node.accessLevel),
          shape: getNodeShape(node.type),
          icon: getNodeIcon(node.type, os),
          nodeType: node.type,
          accessLevel: node.accessLevel,
          os,
          services: node.services?.join(', ') || '',
          ip: node.ip || '',
        },
      })
    }

    for (const edge of g.edges) {
      elements.push({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.label || '',
          color: getEdgeColor(edge.type),
          edgeType: edge.type,
        },
      })
    }

    return elements
  }, [])

  // Initialize or update Cytoscape
  useEffect(() => {
    if (!containerRef.current || !graph || graph.nodes.length === 0) return

    const elements = buildElements(graph)

    if (cyRef.current) {
      // Update existing instance
      cyRef.current.elements().remove()
      cyRef.current.add(elements)
      cyRef.current.layout({
        name: 'dagre',
        rankDir: 'LR',
        spacingFactor: 1.8,
        nodeSep: 80,
        rankSep: 200,
        animate: true,
        animationDuration: 500,
      } as unknown as cytoscape.LayoutOptions).run()
      return
    }

    // Create new Cytoscape instance
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: CY_STYLE,
      layout: {
        name: 'dagre',
        rankDir: 'LR',
        spacingFactor: 1.8,
        nodeSep: 80,
        rankSep: 200,
        animate: false,
      } as unknown as cytoscape.LayoutOptions,
      wheelSensitivity: 0.2,
      minZoom: 0.2,
      maxZoom: 3,
      userPanningEnabled: !compact,
      userZoomingEnabled: !compact,
      boxSelectionEnabled: false,
    })

    cyRef.current = cy

    // Stormspotter click-to-highlight pattern
    cy.on('tap', 'node', (evt) => {
      const node = evt.target
      // Clear previous highlights
      cy.elements().removeClass('outgoing outgoing-node incoming incoming-node dimmed')

      // Dim everything
      cy.elements().addClass('dimmed')

      // Highlight selected node
      node.removeClass('dimmed')

      // Highlight outgoing paths (green)
      node.outgoers().removeClass('dimmed')
      node.outgoers('edge').addClass('outgoing')
      node.outgoers('node').addClass('outgoing-node')

      // Highlight incoming paths (orange)
      node.incomers().removeClass('dimmed')
      node.incomers('edge').addClass('incoming')
      node.incomers('node').addClass('incoming-node')
    })

    // Click background to clear highlights
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass('outgoing outgoing-node incoming incoming-node dimmed')
      }
    })

    // Fit to view
    setTimeout(() => {
      cy.fit(undefined, 50)
      cy.center()
    }, 100)

    return () => {
      cy.destroy()
      cyRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, compact, buildElements])

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
        <svg className="w-12 h-12 text-zinc-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1}
            d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />
        </svg>
        <p className="text-sm">No graph data</p>
        <p className="text-xs text-zinc-600">Connect to a live engagement or data server</p>
      </div>
    )
  }

  return (
    <div className="relative w-full h-full">
      <div
        ref={containerRef}
        className="w-full h-full"
        style={{ backgroundColor: '#0c0f1a' }}
      />

      {/* Legend (bottom-left) */}
      <div className="absolute bottom-4 left-4 bg-card/95 border border-border rounded-lg px-3 py-2 text-xs">
        <p className="text-[9px] font-semibold tracking-widest text-muted-foreground uppercase mb-1.5">
          Access Level
        </p>
        <div className="flex flex-col gap-1">
          {[
            { color: '#ef4444', label: 'SYSTEM' },
            { color: '#f59e0b', label: 'Admin' },
            { color: '#3b82f6', label: 'User' },
            { color: '#6b7280', label: 'Discovered' },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: item.color }} />
              <span className="text-muted-foreground">{item.label}</span>
            </div>
          ))}
        </div>
        <p className="text-[9px] font-semibold tracking-widest text-muted-foreground uppercase mt-2 mb-1">
          Click Highlight
        </p>
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-0.5 rounded" style={{ backgroundColor: '#4ade80' }} />
            <span className="text-muted-foreground">Outgoing</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-0.5 rounded" style={{ backgroundColor: '#fb923c' }} />
            <span className="text-muted-foreground">Incoming</span>
          </div>
        </div>
      </div>
    </div>
  )
}
