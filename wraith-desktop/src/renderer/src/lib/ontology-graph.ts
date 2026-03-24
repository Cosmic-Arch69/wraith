// Ontology Knowledge Graph Materializer
// Takes raw Wraith data (ontology + attack graph + credentials + recon)
// and produces a MiroFish-style knowledge graph of entity instances and relationships.

// ---- Types ----

export interface OntologyNode {
  id: string
  label: string
  entityType: EntityType
  significance?: string
  data: Record<string, unknown>
}

export interface OntologyEdge {
  id: string
  source: string
  target: string
  relationship: string
  label: string
}

export type EntityType =
  | 'Host'
  | 'Service'
  | 'WebApplication'
  | 'Vulnerability'
  | 'Credential'
  | 'DomainController'
  | 'Domain'
  | 'PortForward'
  | 'DiscoveredFile'
  | 'User'

// ---- Color Map (MiroFish-style) ----

export const ENTITY_COLORS: Record<EntityType, string> = {
  Host: '#ef4444',
  Service: '#3b82f6',
  WebApplication: '#8b5cf6',
  Vulnerability: '#f97316',
  Credential: '#eab308',
  DomainController: '#dc2626',
  Domain: '#14b8a6',
  PortForward: '#f59e0b',
  DiscoveredFile: '#ec4899',
  User: '#6b7280',
}

export const ENTITY_BG_COLORS: Record<EntityType, string> = {
  Host: '#fef2f2',
  Service: '#eff6ff',
  WebApplication: '#f5f3ff',
  Vulnerability: '#fff7ed',
  Credential: '#fefce8',
  DomainController: '#fef2f2',
  Domain: '#f0fdfa',
  PortForward: '#fffbeb',
  DiscoveredFile: '#fdf2f8',
  User: '#f9fafb',
}

// ---- Raw data types from API ----

interface RawGraphNode {
  host: string
  ip: string
  status: string
  services: string[]
  access_level: string
  soar_status?: string
  vectors_open?: string[]
  notes?: string[]
}

interface RawGraph {
  nodes: Record<string, RawGraphNode>
  edges: Array<{ from: string; to: string; via: string }>
  wan_ip?: string
  pivot_points?: string[]
}

interface RawCredential {
  id: string
  username: string
  password?: string
  hash?: string
  source: string
  scope: string
  hosts_valid: string[]
  discovered_at: string
}

interface RawNotableEntity {
  type: string
  name: string
  host: string
  significance: string
}

interface RawOntology {
  entity_types: Array<{ name: string; description: string; attributes: unknown[]; examples: string[] }>
  edge_types: Array<{ name: string; description: string; source_types: string[]; target_types: string[] }>
  notable_entities: RawNotableEntity[]
}

interface RawReconHost {
  ip: string
  hostname?: string
  os?: string
  ports?: Array<{ port: number; protocol: string; service: string; version?: string }>
  services?: string[]
}

interface RawRecon {
  hosts?: RawReconHost[]
  domain?: string
  dc_ip?: string
}

// ---- Materializer ----

export function materializeOntologyGraph(
  ontology: RawOntology | null,
  attackGraph: RawGraph | null,
  credentials: RawCredential[],
  recon: RawRecon | null,
): { nodes: OntologyNode[]; edges: OntologyEdge[] } {
  const nodes: OntologyNode[] = []
  const edges: OntologyEdge[] = []
  const nodeIds = new Set<string>()

  function addNode(node: OntologyNode): void {
    if (!nodeIds.has(node.id)) {
      nodeIds.add(node.id)
      nodes.push(node)
    }
  }

  function addEdge(source: string, target: string, relationship: string): void {
    if (nodeIds.has(source) && nodeIds.has(target) && source !== target) {
      const id = `${source}-${relationship}-${target}`
      if (!edges.some((e) => e.id === id)) {
        edges.push({ id, source, target, relationship, label: relationship })
      }
    }
  }

  // 1. Create Host nodes from attack graph
  // Handle both formats: Record<ip, node> (Wraith raw) and Array<node> (Console format)
  if (attackGraph?.nodes) {
    const nodeEntries: Array<[string, RawGraphNode]> = Array.isArray(attackGraph.nodes)
      ? (attackGraph.nodes as Array<{ ip: string; label?: string; host?: string; status?: string; services?: string[]; access_level?: string; accessLevel?: string; soar_status?: string; tags?: string[] }>)
          .filter((n) => n.ip)
          .map((n) => [n.ip, {
            host: n.label || n.host || n.ip,
            ip: n.ip,
            status: n.status || 'up',
            services: n.services || [],
            access_level: n.access_level || n.accessLevel || 'none',
            soar_status: n.soar_status || (n.tags?.includes('blocked') ? 'blocked' : undefined),
          } as RawGraphNode])
      : Object.entries(attackGraph.nodes)

    for (const [ip, node] of nodeEntries) {
      addNode({
        id: `host:${ip}`,
        label: node.host || ip,
        entityType: 'Host',
        data: {
          ip,
          hostname: node.host,
          status: node.status,
          access_level: node.access_level,
          services: node.services,
          soar_status: node.soar_status,
        },
      })
    }
  }

  // 2. Create Service nodes from recon data (each port = separate entity)
  if (recon?.hosts) {
    for (const host of recon.hosts) {
      const hostId = `host:${host.ip}`
      if (host.ports) {
        for (const port of host.ports) {
          const svcId = `svc:${host.ip}:${port.port}`
          const svcName = port.service || `port-${port.port}`
          addNode({
            id: svcId,
            label: `${svcName}:${port.port}`,
            entityType: 'Service',
            data: {
              port: port.port,
              protocol: port.protocol,
              service: port.service,
              version: port.version,
              host_ip: host.ip,
            },
          })
          addEdge(hostId, svcId, 'RUNS_SERVICE')
        }
      }
      // Also from services array (attack-graph format "service:port")
      if (!host.ports && host.services) {
        // skip -- handled below
      }
    }
  }

  // Also create services from attack graph service strings
  if (attackGraph?.nodes) {
    const entries: Array<[string, { services?: string[] }]> = Array.isArray(attackGraph.nodes)
      ? (attackGraph.nodes as Array<{ ip: string; services?: string[] }>).filter(n => n.ip).map(n => [n.ip, n])
      : Object.entries(attackGraph.nodes)
    for (const [ip, node] of entries) {
      const hostId = `host:${ip}`
      for (const svcStr of node.services || []) {
        const parts = svcStr.split(':')
        if (parts.length === 2) {
          const [svcName, port] = parts
          const svcId = `svc:${ip}:${port}`
          if (!nodeIds.has(svcId)) {
            addNode({
              id: svcId,
              label: `${svcName}:${port}`,
              entityType: 'Service',
              data: { port: parseInt(port, 10), service: svcName, host_ip: ip },
            })
          }
          addEdge(hostId, svcId, 'RUNS_SERVICE')
        }
      }
    }
  }

  // 3. Create notable entity nodes (WebApps, Vulnerabilities, Files, DCs, PortForwards)
  if (ontology?.notable_entities) {
    for (const notable of ontology.notable_entities) {
      const entityType = mapNotableType(notable.type)
      const nodeId = `notable:${notable.name.substring(0, 30).replace(/\s/g, '_')}`

      addNode({
        id: nodeId,
        label: notable.name,
        entityType,
        significance: notable.significance,
        data: {
          host: notable.host,
          type: notable.type,
          significance: notable.significance,
        },
      })

      // Connect to host
      const hostId = `host:${notable.host}`
      if (nodeIds.has(hostId)) {
        const rel = getRelationshipForNotable(entityType)
        addEdge(hostId, nodeId, rel)
      }
    }
  }

  // 4. Create Credential nodes
  for (const cred of credentials) {
    const credId = `cred:${cred.username}`
    addNode({
      id: credId,
      label: cred.username,
      entityType: 'Credential',
      data: {
        username: cred.username,
        hasPassword: !!cred.password,
        hasHash: !!cred.hash,
        source: cred.source,
        scope: cred.scope,
        hosts_valid: cred.hosts_valid,
      },
    })

    // Connect credentials to valid hosts
    for (const validHost of cred.hosts_valid || []) {
      addEdge(credId, `host:${validHost}`, 'AUTHENTICATES_TO')
    }
  }

  // 5. Create Domain node
  if (recon?.domain) {
    const domainId = `domain:${recon.domain}`
    addNode({
      id: domainId,
      label: recon.domain,
      entityType: 'Domain',
      data: { fqdn: recon.domain, dc_ip: recon.dc_ip },
    })

    // DC is member of domain
    if (recon.dc_ip) {
      const dcHostId = `host:${recon.dc_ip}`
      addEdge(dcHostId, domainId, 'MEMBER_OF')

      // Also create a DomainController node
      const dcId = `dc:${recon.dc_ip}`
      addNode({
        id: dcId,
        label: `DC1.${recon.domain}`,
        entityType: 'DomainController',
        data: { ip: recon.dc_ip, domain: recon.domain },
      })
      addEdge(dcId, domainId, 'MEMBER_OF')
      addEdge(dcHostId, dcId, 'CONNECTS_TO')
    }

    // All hosts are domain members
    if (attackGraph?.nodes) {
      const ips: string[] = Array.isArray(attackGraph.nodes)
        ? (attackGraph.nodes as Array<{ ip: string }>).map((n) => n.ip).filter(Boolean)
        : Object.keys(attackGraph.nodes)
      for (const ip of ips) {
        if (ip !== recon.dc_ip) {
          addEdge(`host:${ip}`, domainId, 'MEMBER_OF')
        }
      }
    }
  }

  // 6. Create Host-to-Host connections from attack graph edges
  if (attackGraph?.edges) {
    for (const edge of attackGraph.edges) {
      const fromId = `host:${edge.from}`
      const toId = `host:${edge.to}`
      if (nodeIds.has(fromId) && nodeIds.has(toId)) {
        addEdge(fromId, toId, 'CONNECTS_TO')
      }
    }
  }

  return { nodes, edges }
}

// ---- Helpers ----

function mapNotableType(type: string): EntityType {
  const map: Record<string, EntityType> = {
    WebApplication: 'WebApplication',
    Vulnerability: 'Vulnerability',
    DomainController: 'DomainController',
    PortForward: 'PortForward',
    DiscoveredFile: 'DiscoveredFile',
    Credential: 'Credential',
    Domain: 'Domain',
    Host: 'Host',
    Service: 'Service',
    User: 'User',
  }
  return map[type] || 'Host'
}

function getRelationshipForNotable(entityType: EntityType): string {
  const map: Record<EntityType, string> = {
    WebApplication: 'HOSTS_APP',
    Vulnerability: 'HAS_VULNERABILITY',
    DomainController: 'CONNECTS_TO',
    PortForward: 'FORWARDS_TO',
    DiscoveredFile: 'EXPOSES_FILE',
    Credential: 'AUTHENTICATES_TO',
    Domain: 'MEMBER_OF',
    Host: 'CONNECTS_TO',
    Service: 'RUNS_SERVICE',
    User: 'AUTHENTICATES_TO',
  }
  return map[entityType] || 'RELATES_TO'
}
