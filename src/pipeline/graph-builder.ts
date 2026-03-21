// Graph builder -- constructs typed attack graph from recon data + ontology
// Adapted from MiroFish graph_builder.py pattern (without Zep -- uses local AttackGraphService)
// v3: Parses recon deliverable JSON, creates typed nodes/edges, seeds initial vectors

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { AttackGraphService } from '../services/attack-graph.js';
import type { AttackOntology, WraithV3Config } from '../types/index.js';

interface ReconHost {
  ip: string;
  hostname?: string;
  name?: string;
  os?: string;
  status?: string;
  ports?: Array<{
    port: number;
    protocol?: string;
    service?: string;
    version?: string;
    state?: string;
  }>;
  services?: string[] | Record<string, Record<string, string>>;
  open_ports?: number[];
  critical_findings?: string[];
  web_url?: string;
  web_app?: string;
}

interface ReconDeliverable {
  hosts?: ReconHost[];
  live_hosts?: ReconHost[];
  domain?: string;
  dc_ip?: string;
  scan_time?: string;
}

export class GraphBuilder {
  buildFromRecon(
    logDir: string,
    ontology: AttackOntology,
    graphService: AttackGraphService,
    config: WraithV3Config,
  ): void {
    console.log('[graph-builder] Building typed graph from recon data...');

    const reconPath = join(logDir, 'recon_deliverable.json');
    if (!existsSync(reconPath)) {
      console.warn('[graph-builder] No recon_deliverable.json found -- using config hosts only');
      this.seedFromConfig(graphService, config);
      return;
    }

    let recon: ReconDeliverable;
    try {
      recon = JSON.parse(readFileSync(reconPath, 'utf-8'));
    } catch (err) {
      console.warn(`[graph-builder] Failed to parse recon_deliverable.json: ${err}`);
      this.seedFromConfig(graphService, config);
      return;
    }

    const hosts = recon.hosts ?? recon.live_hosts ?? [];

    for (const host of hosts) {
      const ip = host.ip;
      const hostname = host.hostname ?? host.name ?? ip;

      // Init or update node
      graphService.initNode(ip, hostname);

      // Set entity_type via update
      const updates: Record<string, unknown> = {
        host: hostname,
        status: host.status === 'down' ? 'down' : 'up',
      };

      // Parse services from ports array
      const services: string[] = [];
      const vectors: string[] = [];

      if (host.ports) {
        for (const port of host.ports) {
          if (port.state === 'closed') continue;
          const svcName = port.service ?? port.protocol ?? 'unknown';
          services.push(`${svcName}:${port.port}`);

          // Seed vectors based on discovered services
          this.seedVectorsFromPort(port.port, svcName, vectors);
        }
      }

      if (host.services) {
        if (Array.isArray(host.services)) {
          // Array format: ["http:80", "smb:445"]
          for (const svc of host.services) {
            if (!services.includes(svc)) services.push(svc);
          }
        } else if (typeof host.services === 'object') {
          // Dict format: {"80": {proto: "http", ...}, "443": {...}} (BUG-8 fix)
          for (const [port, info] of Object.entries(host.services as Record<string, Record<string, string>>)) {
            const proto = info?.proto ?? info?.protocol ?? 'unknown';
            const svc = `${proto}:${port}`;
            if (!services.includes(svc)) services.push(svc);
            this.seedVectorsFromPort(parseInt(port, 10), proto, vectors);
          }
        }
      }

      // Also use open_ports array if available (BUG-8: recon may provide this)
      // v3.3.0 BUG-22: Map port numbers to service names
      if (host.open_ports) {
        for (const port of host.open_ports) {
          const serviceName = this.portToServiceName(port);
          const svc = `${serviceName}:${port}`;
          if (!services.includes(svc)) services.push(svc);
          this.seedVectorsFromPort(port, serviceName, vectors);
        }
      }

      // v3.2.0 BUG-19: Parse critical_findings from recon and update access_level
      if (host.critical_findings) {
        for (const finding of host.critical_findings) {
          const lower = finding.toLowerCase();
          if (lower.includes('system') && (lower.includes('webshell') || lower.includes('rce'))) {
            (updates as Record<string, unknown>).access_level = 'system';
          } else if (lower.includes('admin') && lower.includes('access')) {
            (updates as Record<string, unknown>).access_level = 'admin';
          }
          if (!updates.notes) updates.notes = [];
          (updates.notes as string[]).push(`[recon] ${finding.substring(0, 100)}`);
        }
      }

      // Check config for web_url to add dvwa/web vectors
      const configHost = config.target.hosts.find(h => h.ip === ip);
      if (configHost?.web_url) {
        vectors.push('web-app');
        if (configHost.web_app === 'dvwa') {
          (updates as Record<string, unknown>).dvwa_available = true;
          vectors.push('dvwa');
        }
      }

      // v3.5.0 BUG-52: Ontology-driven vector seeding
      if (ontology?.notable_entities) {
        for (const entity of ontology.notable_entities) {
          if (entity.host === ip || entity.host === hostname) {
            const eName = entity.name.toLowerCase();
            if (eName.includes('petitpotam')) { if (!vectors.includes('coercion-petitpotam')) vectors.push('coercion-petitpotam'); }
            if (eName.includes('printnightmare')) { if (!vectors.includes('coercion-printnightmare')) vectors.push('coercion-printnightmare'); }
            if (eName.includes('allow_url_include')) { if (!vectors.includes('rfi-webshell')) vectors.push('rfi-webshell'); }
            if (eName.includes('disable_functions')) { if (!vectors.includes('php-rce')) vectors.push('php-rce'); }
            if (eName.includes('default') && eName.includes('cred')) { if (!vectors.includes('default-creds')) vectors.push('default-creds'); }
            if (eName.includes('anonymous')) { if (!vectors.includes('anonymous-access')) vectors.push('anonymous-access'); }
          }
        }
      }

      // BUG-40: Deduplicate services -- remove 'unknown:PORT' when named 'service:PORT' exists
      const namedPorts = new Set<number>();
      for (const svc of services) {
        const parts = svc.split(':');
        if (parts[0] !== 'unknown' && parts[1]) namedPorts.add(parseInt(parts[1], 10));
      }
      const dedupedServices = services.filter(svc => {
        if (!svc.startsWith('unknown:')) return true;
        const port = parseInt(svc.split(':')[1] ?? '0', 10);
        return !namedPorts.has(port);
      });

      graphService.updateNode(ip, {
        ...updates,
        services: dedupedServices,
        vectors_open: vectors,
      } as Parameters<AttackGraphService['updateNode']>[1]);
    }

    // Create edges: all hosts connect to DC (if DC discovered)
    // BUG-4 fix: guard empty DC IP
    const dcIp = recon.dc_ip ?? config.target.dc;
    if (dcIp) {
      for (const host of hosts) {
        if (host.ip !== dcIp) {
          graphService.addEdge(host.ip, dcIp, 'domain-member');
        }
      }
    }

    // Add timeline entry
    graphService.addTimeline('graph-builder', 'graph_built', `${hosts.length} hosts, ontology: ${ontology.entity_types.length} types`);

    console.log(`[graph-builder] Graph built: ${hosts.length} hosts, ${ontology.entity_types.length} entity types`);
  }

  private seedFromConfig(graphService: AttackGraphService, config: WraithV3Config): void {
    for (const host of config.target.hosts) {
      graphService.initNode(host.ip, host.name);
      const vectors: string[] = ['port-scan', 'service-enum'];  // BUG-5 fix: always viable
      if (host.web_url) vectors.push('web-app');
      if (host.web_app === 'dvwa') vectors.push('dvwa');
      graphService.updateNode(host.ip, {
        status: 'unknown' as const,
        vectors_open: vectors,
      });
    }
    // BUG-4 fix: guard empty DC IP
    if (config.target.dc) {
      graphService.initNode(config.target.dc, 'DC');
    }
  }

  private seedVectorsFromPort(port: number, service: string, vectors: string[]): void {
    const add = (v: string) => { if (!vectors.includes(v)) vectors.push(v); };

    switch (port) {
      case 80:
      case 443:
      case 8080:
      case 8443:
      case 3000:
        add('web-app');
        add('sqli');
        add('cmdi');
        add('auth-bypass');
        break;
      case 445:
        add('smb-relay');
        add('smb-brute');
        add('psexec');
        break;
      case 5985:
      case 5986:
        add('winrm');
        break;
      case 3389:
        add('rdp-brute');
        break;
      case 88:
        add('kerberoast');
        add('asreproast');
        break;
      case 389:
      case 636:
        add('ldap-enum');
        break;
      case 135:
        add('dcom');
        break;
      case 22:
        add('ssh-brute');
        break;
    }

    // Service name heuristics
    if (service.includes('http') || service.includes('nginx') || service.includes('apache')) {
      add('web-app');
    }
    if (service.includes('smb') || service.includes('microsoft-ds')) {
      add('smb-relay');
    }
  }

  // v3.3.0 BUG-22: Map common port numbers to human-readable service names
  private portToServiceName(port: number): string {
    const map: Record<number, string> = {
      22: 'ssh', 53: 'dns', 80: 'http', 88: 'kerberos',
      135: 'rpc', 139: 'netbios', 389: 'ldap', 443: 'https',
      445: 'smb', 636: 'ldaps', 3000: 'http-alt', 3306: 'mysql',
      3389: 'rdp', 5432: 'postgresql', 5985: 'winrm', 5986: 'winrm-ssl',
      8080: 'http-proxy', 8443: 'https-alt', 9443: 'https-alt',
    };
    return map[port] ?? 'unknown';
  }
}
