// Ontology generator -- LLM reads recon data and produces typed entity/edge schema
// Adapted from MiroFish ontology_generator.py pattern
// v3: Runs once after recon, before graph construction

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runAgent } from '../ai/claude-executor.js';
import { loadPrompt } from '../services/prompt-manager.js';
import type { AttackOntology, OntologyEntityType, WraithV3Config } from '../types/index.js';

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
      return this.validate(parsed);
    } catch (err) {
      console.warn(`[ontology] Failed to parse LLM output: ${err} -- using fallback`);
      return this.fallbackOntology();
    }
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
