import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Brain, RefreshCw, AlertTriangle } from 'lucide-react'
import { OntologyGraphCanvas } from '@/components/graph/ontology-graph-canvas'
import {
  materializeOntologyGraph,
  type OntologyNode,
  type OntologyEdge,
} from '@/lib/ontology-graph'

const BASE_URL = 'http://localhost:3001'

export default function OntologyPage(): React.JSX.Element {
  const [nodes, setNodes] = useState<OntologyNode[]>([])
  const [edges, setEdges] = useState<OntologyEdge[]>([])
  const [notableEntities, setNotableEntities] = useState<
    Array<{ type: string; name: string; host: string; significance: string }>
  >([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showEdgeLabels, setShowEdgeLabels] = useState(true)
  const [showNotables, setShowNotables] = useState(true)

  const fetchAndBuild = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [ontologyRes, graphRes, credsRes] = await Promise.allSettled([
        fetch(`${BASE_URL}/api/ontology`).then((r) => (r.ok ? r.json() : null)),
        fetch(`${BASE_URL}/api/graph`).then((r) => (r.ok ? r.json() : null)),
        fetch(`${BASE_URL}/api/credentials`).then((r) => (r.ok ? r.json() : [])),
      ])

      const ontology = ontologyRes.status === 'fulfilled' ? ontologyRes.value : null
      const graph = graphRes.status === 'fulfilled' ? graphRes.value : null
      const creds = credsRes.status === 'fulfilled' ? credsRes.value : []

      // Try to get recon data (may not exist in mock server)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let recon: any = null
      try {
        const reconRes2 = await fetch(`${BASE_URL}/api/ontology`)
        if (reconRes2.ok) {
          const ontData = await reconRes2.json()
          // Extract domain info from notable entities
          if (ontData?.notable_entities) {
            const dcEntity = ontData.notable_entities.find(
              (e: { type: string }) => e.type === 'DomainController'
            )
            if (dcEntity) {
              recon = {
                domain: 'YASHnet.local',
                dc_ip: '172.16.20.5',
                hosts: [],
              }
            }
          }
        }
      } catch {
        // non-critical
      }

      if (!ontology && !graph) {
        setError('No ontology or graph data available. Connect to a running engagement or data server.')
        setLoading(false)
        return
      }

      const { nodes: materializedNodes, edges: materializedEdges } = materializeOntologyGraph(
        ontology,
        graph,
        creds,
        recon
      )

      setNodes(materializedNodes)
      setEdges(materializedEdges)
      setNotableEntities(ontology?.notable_entities || [])
    } catch (err) {
      setError(`Failed to fetch data: ${err}`)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchAndBuild()
  }, [fetchAndBuild])

  // Count entity types
  const entityTypeCounts: Record<string, number> = {}
  for (const node of nodes) {
    entityTypeCounts[node.entityType] = (entityTypeCounts[node.entityType] || 0) + 1
  }

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <Brain className="w-5 h-5 text-purple-600" />
          <h1 className="text-lg font-semibold">Knowledge Graph</h1>
          <Badge variant="outline" className="text-xs font-mono">
            {nodes.length} entities
          </Badge>
          <Badge variant="outline" className="text-xs font-mono">
            {edges.length} relationships
          </Badge>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-zinc-500 cursor-pointer">
            <input
              type="checkbox"
              checked={showEdgeLabels}
              onChange={(e) => setShowEdgeLabels(e.target.checked)}
              className="rounded border-zinc-300"
            />
            Edge Labels
          </label>
          <label className="flex items-center gap-2 text-xs text-zinc-500 cursor-pointer">
            <input
              type="checkbox"
              checked={showNotables}
              onChange={(e) => setShowNotables(e.target.checked)}
              className="rounded border-zinc-300"
            />
            Notable Entities
          </label>
          <Button variant="outline" size="sm" onClick={fetchAndBuild} className="h-7 text-xs">
            <RefreshCw className="w-3 h-3 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 min-h-0 flex gap-4">
        {/* Graph canvas */}
        <div className="flex-1 min-w-0 rounded-lg border border-border overflow-hidden bg-card">
          {loading ? (
            <div className="flex items-center justify-center h-full text-zinc-400">
              <div className="text-center">
                <Brain className="w-8 h-8 mx-auto mb-2 animate-pulse" />
                <p className="text-sm">Building knowledge graph...</p>
              </div>
            </div>
          ) : error ? (
            <div className="flex items-center justify-center h-full text-zinc-400">
              <div className="text-center">
                <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-amber-500" />
                <p className="text-sm">{error}</p>
              </div>
            </div>
          ) : (
            <OntologyGraphCanvas
              nodes={nodes}
              edges={edges}
              showEdgeLabels={showEdgeLabels}
            />
          )}
        </div>

        {/* Notable entities sidebar */}
        {showNotables && notableEntities.length > 0 && (
          <div className="w-80 shrink-0 overflow-auto">
            <div className="space-y-3">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-zinc-400">
                Notable Entities ({notableEntities.length})
              </h2>
              {notableEntities.map((entity, i) => {
                const severity = entity.significance.includes('CRITICAL')
                  ? 'critical'
                  : entity.significance.includes('HIGH')
                    ? 'high'
                    : 'medium'
                const severityColor =
                  severity === 'critical'
                    ? 'border-red-500/30 bg-red-950/40'
                    : severity === 'high'
                      ? 'border-orange-500/30 bg-orange-950/40'
                      : 'border-yellow-500/30 bg-yellow-950/40'
                const badgeColor =
                  severity === 'critical'
                    ? 'bg-red-900/60 text-red-300'
                    : severity === 'high'
                      ? 'bg-orange-900/60 text-orange-300'
                      : 'bg-yellow-900/60 text-yellow-300'

                return (
                  <Card key={i} className={`${severityColor} border`}>
                    <CardContent className="p-3">
                      <div className="flex items-start gap-2 mb-1">
                        <Badge className={`${badgeColor} text-[9px] shrink-0`}>
                          {severity.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-[9px] shrink-0 border-border">
                          {entity.type}
                        </Badge>
                      </div>
                      <p className="text-xs font-semibold text-foreground mb-1">{entity.name}</p>
                      <p className="text-[10px] text-muted-foreground leading-relaxed">
                        {entity.significance.replace(/^(CRITICAL|HIGH|MEDIUM)[\s—-]+/, '')}
                      </p>
                      <p className="text-[9px] text-zinc-400 mt-1 font-mono">{entity.host}</p>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
