// MCP tool definitions and handlers for the live attack graph
// v2.1 Features: F3 (Attack Graph), F8 (SOAR Detection), F10 (DVWA tracking)

import { AttackGraphService } from '../services/attack-graph.js';

// ---------------------------------------------------------------------------
// Tool definitions (MCP inputSchema format)
// ---------------------------------------------------------------------------

export const GRAPH_TOOLS = [
  {
    name: 'graph_update',
    description: 'Update a node in the live attack graph with discovered info, service data, or timing.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ip: { type: 'string', description: 'Target IP address (required)' },
        host: { type: 'string', description: 'Hostname or label for the node' },
        status: {
          type: 'string',
          enum: ['up', 'down', 'blocked', 'unknown'],
          description: 'Node reachability status',
        },
        services: {
          type: 'array',
          items: { type: 'string' },
          description: 'Discovered services, e.g. ["smb:445", "http:3000"]',
        },
        access_level: {
          type: 'string',
          enum: ['none', 'user', 'admin', 'system'],
          description: 'Access level achieved on the host',
        },
        vectors_open: {
          type: 'array',
          items: { type: 'string' },
          description: 'Attack vectors that are still viable',
        },
        vectors_blocked: {
          type: 'array',
          items: { type: 'string' },
          description: 'Attack vectors that are confirmed dead',
        },
        dvwa_available: {
          type: 'boolean',
          description: 'Whether DVWA is reachable on this host',
        },
        notes: {
          type: 'array',
          items: { type: 'string' },
          description: 'Arbitrary findings or observations',
        },
        response_time_ms: {
          type: 'number',
          description: 'Latest response time in ms (0 = timeout). Used for SOAR block detection.',
        },
      },
      required: ['ip'],
    },
  },
  {
    name: 'graph_query',
    description: 'Query the live attack graph for node details, blocked hosts, open vectors, or a summary.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        query_type: {
          type: 'string',
          enum: ['node', 'all', 'blocked', 'open_vectors', 'summary', 'detect_block', 'by_entity_type', 'detailed_summary', 'viable_attack_paths'],
          description:
            'node: single host details | all: full graph JSON | blocked: IPs with status=blocked | open_vectors: viable attack paths | summary: markdown overview | detect_block: check if IP is being blocked by SOAR | by_entity_type: filter by entity_type | detailed_summary: rich planner output | viable_attack_paths: ordered viable vectors',
        },
        ip: {
          type: 'string',
          description: 'Required for query_type=node and detect_block. Optional filter for open_vectors.',
        },
      },
      required: ['query_type'],
    },
  },
] as const;

// ---------------------------------------------------------------------------
// Tool name constants
// ---------------------------------------------------------------------------

export const GRAPH_TOOL_NAMES = ['graph_update', 'graph_query'] as const;

// ---------------------------------------------------------------------------
// Singleton instance
// ---------------------------------------------------------------------------

let _instance: AttackGraphService | undefined;

function getInstance(): AttackGraphService {
  if (!_instance) {
    const logDir = process.env.WRAITH_LOG_DIR ?? './attack-logs';
    _instance = new AttackGraphService(logDir);
  }
  return _instance;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export function handleGraphTool(name: string, input: Record<string, unknown>): string {
  const svc = getInstance();

  switch (name) {

    case 'graph_update': {
      const ip = input.ip as string;

      // Auto-init node if not present (use provided host or ip as label)
      const host = (input.host as string | undefined) ?? ip;
      svc.initNode(ip, host);

      // Build the update payload -- only include fields that were provided
      const updates: Parameters<AttackGraphService['updateNode']>[1] = {};

      if (input.host !== undefined) updates.host = input.host as string;
      if (input.status !== undefined) {
        updates.status = input.status as 'up' | 'down' | 'blocked' | 'unknown';
      }
      if (input.access_level !== undefined) {
        // v3.6.0 BUG-NEW-4/7: Log MCP access level updates (monotonic guard is in attack-graph.ts updateNode)
        const currentNode = svc.queryNode(ip);
        const currentLevel = currentNode?.access_level ?? 'none';
        const proposed = input.access_level as string;
        const RANK: Record<string, number> = { 'none': 0, 'user': 1, 'admin': 2, 'system': 3 };
        if ((RANK[proposed] ?? 0) <= (RANK[currentLevel] ?? 0) && proposed !== currentLevel) {
          console.log(`  [graph-guard] MCP blocked access_level downgrade on ${ip}: ${currentLevel} -> ${proposed}`);
        }
        updates.access_level = input.access_level as 'none' | 'user' | 'admin' | 'system';
      }
      if (Array.isArray(input.services)) updates.services = input.services as string[];
      if (Array.isArray(input.vectors_open)) updates.vectors_open = input.vectors_open as string[];
      if (Array.isArray(input.vectors_blocked)) updates.vectors_blocked = input.vectors_blocked as string[];
      if (Array.isArray(input.notes)) updates.notes = input.notes as string[];
      if (input.dvwa_available !== undefined) updates.dvwa_available = input.dvwa_available as boolean;

      // Handle response_time_ms separately -- goes through recordResponseTime
      if (input.response_time_ms !== undefined) {
        svc.recordResponseTime(ip, input.response_time_ms as number);
      }

      svc.updateNode(ip, updates);

      return `graph_update: node ${ip} updated`;
    }

    case 'graph_query': {
      const queryType = input.query_type as string;
      const ip = input.ip as string | undefined;

      switch (queryType) {
        case 'node': {
          if (!ip) return 'graph_query error: ip is required for query_type=node';
          const node = svc.queryNode(ip);
          if (!node) return `graph_query: no node found for ${ip}`;
          return JSON.stringify(node, null, 2);
        }

        case 'all': {
          return svc.toJSON();
        }

        case 'blocked': {
          const blocked = svc.getBlocked();
          if (blocked.length === 0) return 'graph_query: no blocked hosts';
          return `Blocked hosts (${blocked.length}):\n${blocked.join('\n')}`;
        }

        case 'open_vectors': {
          const vectors = svc.queryOpenVectors(ip);
          if (vectors.length === 0) return 'graph_query: no open vectors found';
          return vectors
            .map((v) => `${v.host}: ${v.vectors.join(', ')}`)
            .join('\n');
        }

        case 'summary': {
          return svc.getSummary();
        }

        case 'detect_block': {
          if (!ip) return 'graph_query error: ip is required for query_type=detect_block';
          const isBlocked = svc.detectBlock(ip);
          return isBlocked
            ? `BLOCKED: SOAR block detected for ${ip} -- last response times triggered threshold`
            : `OK: No block pattern detected for ${ip}`;
        }

        case 'by_entity_type': {
          const entityType = ip; // reuse ip param for entity type
          if (!entityType) return 'graph_query error: ip param (used as entity_type) is required for by_entity_type';
          const nodes = svc.queryByEntityType(entityType);
          if (nodes.length === 0) return `No nodes with entity_type="${entityType}"`;
          return JSON.stringify(nodes, null, 2);
        }

        case 'detailed_summary': {
          return svc.getDetailedSummary();
        }

        case 'viable_attack_paths': {
          const viableVectors = svc.getViableVectors();
          if (viableVectors.length === 0) return 'No viable attack paths remaining';
          return viableVectors
            .map((v, i) => `${i + 1}. ${v.host} (${v.ip}) [priority=${v.priority}]: ${v.vectors.join(', ')}`)
            .join('\n');
        }

        default:
          return `graph_query: unknown query_type "${queryType}"`;
      }
    }

    default:
      return `handleGraphTool: unknown tool "${name}"`;
  }
}
