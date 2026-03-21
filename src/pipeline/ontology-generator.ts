// Ontology generator -- LLM reads recon data and produces typed entity/edge schema
// Adapted from MiroFish ontology_generator.py pattern
// v3: Runs once after recon, before graph construction

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runAgent } from '../ai/claude-executor.js';
import { loadPrompt } from '../services/prompt-manager.js';
import type { AttackOntology, NotableEntity, OntologyEntityType, WraithV3Config } from '../types/index.js';

const REQUIRED_ENTITY_TYPES = ['Host', 'Service', 'Vulnerability', 'Credential', 'User'];
const REQUIRED_EDGE_TYPES = [
  'RUNS_SERVICE',
  'HAS_VULNERABILITY',
  'AUTHENTICATES_TO',
  'TRUSTS',
  'CONNECTS_TO',
];
const MAX_ENTITY_TYPES = 10;
const MAX_EDGE_TYPES = 10;

export class OntologyGenerator {
  async generate(reconData: string, _config: WraithV3Config): Promise<AttackOntology> {
    // BUG-2 fix: skip LLM call when recon data is empty (saves API call)
    if (!reconData || reconData.trim().length < 10) {
      console.log('[ontology] No recon data available -- using fallback ontology');
      return this.fallbackOntology();
    }

    console.log('[ontology] Generating attack ontology from recon data...');

    const prompt = await loadPrompt('ontology', {
      recon_data: reconData.substring(0, 15_000), // cap to avoid context overflow
    });

    const result = await runAgent(prompt, 'ontology-generator', 'small', {}, 10);

    if (!result.success || !result.result) {
      console.warn('[ontology] LLM generation failed -- using fallback ontology');
      return this.fallbackOntology();
    }

    try {
      const parsed = this.extractJSON(result.result);
      const validated = this.validate(parsed);

      // v3.5.0 BUG-52: Extract notable entities from recon data
      // LLM may return them; if not, extract heuristically
      if (!validated.notable_entities || validated.notable_entities.length === 0) {
        validated.notable_entities = this.extractNotableEntities(reconData);
      }
      console.log(`[ontology] Notable entities: ${validated.notable_entities.length}`);

      return validated;
    } catch (err) {
      console.warn(`[ontology] Failed to parse LLM output: ${err} -- using fallback`);
      return this.fallbackOntology();
    }
  }

  // v3.5.0 BUG-52: Heuristic extraction of high-value entities from recon data
  private extractNotableEntities(reconData: string): NotableEntity[] {
    const entities: NotableEntity[] = [];
    const lower = reconData.toLowerCase();

    // Try to parse recon as JSON to get host IPs
    let hosts: Array<{ ip: string; hostname?: string; name?: string }> = [];
    try {
      const parsed = JSON.parse(reconData);
      hosts = parsed.hosts ?? parsed.live_hosts ?? [];
    } catch { /* not JSON, scan as text */ }

    const defaultHost = hosts[0]?.ip ?? 'unknown';

    // Helper: find which host a finding is associated with
    const findHost = (keyword: string): string => {
      // Search in each host's data for the keyword
      for (const h of hosts) {
        const hostStr = JSON.stringify(h).toLowerCase();
        if (hostStr.includes(keyword.toLowerCase())) {
          return h.ip;
        }
      }
      return defaultHost;
    };

    // RPCEndpoint mentions
    if (lower.includes('ms-efsrpc') || lower.includes('petitpotam')) {
      entities.push({
        type: 'RPCEndpoint',
        name: 'PetitPotam (MS-EFSRPC)',
        host: findHost('efsrpc'),
        significance: 'Coercion attack vector -- can force NTLM authentication from DC',
      });
    }
    if (lower.includes('ms-rprn') || lower.includes('printnightmare') || lower.includes('print spooler')) {
      entities.push({
        type: 'RPCEndpoint',
        name: 'PrintNightmare (MS-RPRN)',
        host: findHost('rprn'),
        significance: 'Print spooler RCE/coercion -- remote code execution or NTLM relay',
      });
    }
    if (lower.includes('ms-drsr') || lower.includes('dcsync') || lower.includes('drsuapi')) {
      entities.push({
        type: 'RPCEndpoint',
        name: 'DCSync (MS-DRSR/DRSUAPI)',
        host: findHost('drsr'),
        significance: 'Domain replication interface -- DCSync credential extraction',
      });
    }

    // WebApplication misconfigs
    if (lower.includes('allow_url_include') && (lower.includes('on') || lower.includes('1'))) {
      entities.push({
        type: 'WebApplication',
        name: 'allow_url_include=ON',
        host: findHost('allow_url_include'),
        significance: 'Remote File Inclusion enabled -- webshell upload vector',
      });
    }
    if (lower.includes('disable_functions') && (lower.includes('none') || lower.includes('no value'))) {
      entities.push({
        type: 'Vulnerability',
        name: 'PHP disable_functions=NONE',
        host: findHost('disable_functions'),
        significance: 'All PHP functions available -- direct system() code execution',
      });
    }

    // Known vulnerable services
    const apacheMatch = reconData.match(/apache[\/\s]*([\d.]+)/i);
    if (apacheMatch) {
      const ver = apacheMatch[1];
      if (ver.startsWith('2.4.4') && parseInt(ver.split('.')[2] ?? '99', 10) < 50) {
        entities.push({
          type: 'Vulnerability',
          name: `Apache ${ver} (outdated)`,
          host: findHost('apache'),
          significance: 'Outdated Apache version -- check for path traversal, mod_cgi exploits',
        });
      }
    }
    const phpMatch = reconData.match(/php[\/\s]*([\d.]+)/i);
    if (phpMatch) {
      const ver = phpMatch[1];
      entities.push({
        type: 'Vulnerability',
        name: `PHP ${ver}`,
        host: findHost('php'),
        significance: 'PHP version detected -- check for version-specific RCE (CVE-2024-4577 etc)',
      });
    }

    // Default credentials
    if (lower.includes('default') && (lower.includes('credential') || lower.includes('password') || lower.includes('cred'))) {
      entities.push({
        type: 'Credential',
        name: 'Default credentials detected',
        host: findHost('default'),
        significance: 'Default credentials in use -- immediate access without brute force',
      });
    }

    // Anonymous access
    if (lower.includes('anonymous') && (lower.includes('ldap') || lower.includes('smb') || lower.includes('rpc') || lower.includes('ftp'))) {
      const proto = lower.includes('ldap') ? 'LDAP' : lower.includes('smb') ? 'SMB' : lower.includes('ftp') ? 'FTP' : 'RPC';
      entities.push({
        type: 'Vulnerability',
        name: `Anonymous ${proto} access`,
        host: findHost('anonymous'),
        significance: `Unauthenticated ${proto} access -- enumerate users, shares, or directory structure`,
      });
    }

    // DVWA detection
    if (lower.includes('dvwa')) {
      entities.push({
        type: 'WebApplication',
        name: 'DVWA (Damn Vulnerable Web Application)',
        host: findHost('dvwa'),
        significance: 'Intentionally vulnerable web app -- SQLi, CMDi, file upload, RFI vectors',
      });
    }

    return entities;
  }

  validate(ontology: AttackOntology): AttackOntology {
    // Ensure all required entity types exist
    const existingTypes = new Set(ontology.entity_types.map(t => t.name));
    for (const required of REQUIRED_ENTITY_TYPES) {
      if (!existingTypes.has(required)) {
        ontology.entity_types.push({
          name: required,
          description: `${required} entity (auto-added)`,
          attributes: [],
          examples: [],
        });
      }
    }

    // Ensure all required edge types exist
    const existingEdges = new Set(ontology.edge_types.map(t => t.name));
    for (const required of REQUIRED_EDGE_TYPES) {
      if (!existingEdges.has(required)) {
        ontology.edge_types.push({
          name: required,
          description: `${required} relationship (auto-added)`,
          source_types: [],
          target_types: [],
        });
      }
    }

    // Cap counts
    ontology.entity_types = ontology.entity_types.slice(0, MAX_ENTITY_TYPES);
    ontology.edge_types = ontology.edge_types.slice(0, MAX_EDGE_TYPES);

    // v3.5.0 BUG-52: Ensure notable_entities array exists
    if (!ontology.notable_entities) {
      ontology.notable_entities = [];
    }

    // Ensure timestamp
    if (!ontology.generated_at) {
      ontology.generated_at = new Date().toISOString();
    }

    return ontology;
  }

  static loadFromDisk(logDir: string): AttackOntology | null {
    const path = join(logDir, 'ontology.json');
    try {
      return JSON.parse(readFileSync(path, 'utf-8')) as AttackOntology;
    } catch {
      return null;
    }
  }

  private extractJSON(text: string): AttackOntology {
    // Try to extract JSON from LLM response -- handle markdown fences
    const fenced = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
    const jsonStr = fenced ? fenced[1] : text;

    // Find the first { and last }
    const start = jsonStr.indexOf('{');
    const end = jsonStr.lastIndexOf('}');
    if (start === -1 || end === -1) throw new Error('No JSON object found');

    return JSON.parse(jsonStr.substring(start, end + 1));
  }

  private fallbackOntology(): AttackOntology {
    return {
      entity_types: REQUIRED_ENTITY_TYPES.map(name => ({
        name,
        description: `${name} entity`,
        attributes: this.defaultAttributes(name),
        examples: [],
      })),
      edge_types: REQUIRED_EDGE_TYPES.map(name => ({
        name,
        description: `${name} relationship`,
        source_types: [],
        target_types: [],
      })),
      notable_entities: [],
      generated_at: new Date().toISOString(),
    };
  }

  private defaultAttributes(entityType: string): OntologyEntityType['attributes'] {
    switch (entityType) {
      case 'Host':
        return [
          { name: 'ip', type: 'string', description: 'IP address' },
          { name: 'hostname', type: 'string', description: 'Hostname' },
          { name: 'os', type: 'string', description: 'Operating system' },
          { name: 'status', type: 'string', description: 'Reachability status' },
        ];
      case 'Service':
        return [
          { name: 'port', type: 'number', description: 'Port number' },
          { name: 'protocol', type: 'string', description: 'Protocol name' },
          { name: 'version', type: 'string', description: 'Service version' },
        ];
      case 'Vulnerability':
        return [
          { name: 'cve', type: 'string', description: 'CVE identifier' },
          { name: 'severity', type: 'string', description: 'Severity level' },
        ];
      case 'Credential':
        return [
          { name: 'username', type: 'string', description: 'Username' },
          { name: 'scope', type: 'string', description: 'Credential scope' },
        ];
      case 'User':
        return [
          { name: 'username', type: 'string', description: 'Username' },
          { name: 'groups', type: 'string[]', description: 'Group memberships' },
        ];
      default:
        return [];
    }
  }
}
