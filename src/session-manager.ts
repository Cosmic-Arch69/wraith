// Agent registry and DAG for Wraith
// 9 agents across 6 attack phases: recon -> web+creds parallel -> lateral -> privesc -> report
// v3: Added AGENT_TEMPLATE_LIBRARY for adaptive pipeline planner

import type { AgentDefinition, AgentName, EngagementType, ModelTier } from './types/index.js';

export const AGENTS: Readonly<Partial<Record<AgentName, AgentDefinition>>> & Record<string, AgentDefinition> = Object.freeze({

  // Phase 0: OSINT / External Recon (only runs in external engagement mode)
  // NOTE: runner must pass wan_ip from config.engagement?.wan_ip as a prompt template variable
  'osint-recon': {
    name: 'osint-recon',
    displayName: 'OSINT/External Recon agent',
    prerequisites: [],
    promptTemplate: 'osint-recon',
    deliverableFilename: 'osint_deliverable.json',
    modelTier: 'medium',
    timeout_sec: 600,
  },

  // Phase 1: Reconnaissance (sequential entry point)
  'recon': {
    name: 'recon',
    displayName: 'Recon agent',
    prerequisites: [],
    promptTemplate: 'recon',
    deliverableFilename: 'recon_deliverable.json',
    modelTier: 'medium',
  },

  // Phase 2: Web exploitation (3 parallel, all depend on recon)
  'sqli': {
    name: 'sqli',
    displayName: 'SQL injection agent',
    prerequisites: ['recon'],
    promptTemplate: 'sqli',
    deliverableFilename: 'sqli_evidence.md',
    usePlaywright: true,
  },
  'cmdi': {
    name: 'cmdi',
    displayName: 'Command injection agent',
    prerequisites: ['recon'],
    promptTemplate: 'cmdi',
    deliverableFilename: 'cmdi_evidence.md',
    usePlaywright: true,
  },
  'auth-attack': {
    name: 'auth-attack',
    displayName: 'Web auth attack agent',
    prerequisites: ['recon'],
    promptTemplate: 'auth-attack',
    deliverableFilename: 'auth_attack_evidence.md',
    usePlaywright: true,
  },

  // Phase 3: Credential attacks (2 parallel, depend on recon)
  'kerberoast': {
    name: 'kerberoast',
    displayName: 'Kerberoasting agent',
    prerequisites: ['recon'],
    promptTemplate: 'kerberoast',
    deliverableFilename: 'kerberoast_evidence.md',
    modelTier: 'medium',
  },
  'bruteforce': {
    name: 'bruteforce',
    displayName: 'SMB/AD brute force agent',
    prerequisites: ['recon'],
    promptTemplate: 'bruteforce',
    deliverableFilename: 'bruteforce_evidence.md',
  },

  // Phase 4: Lateral movement (sequential, depends on kerberoast + bruteforce)
  'lateral': {
    name: 'lateral',
    displayName: 'Lateral movement agent',
    prerequisites: ['kerberoast', 'bruteforce'],
    promptTemplate: 'lateral',
    deliverableFilename: 'lateral_evidence.md',
    modelTier: 'medium',
  },

  // Phase 5: Privilege escalation (sequential, depends on lateral)
  'privesc': {
    name: 'privesc',
    displayName: 'Privilege escalation agent',
    prerequisites: ['lateral'],
    promptTemplate: 'privesc',
    deliverableFilename: 'privesc_evidence.md',
    modelTier: 'large',
  },

  // Phase 6: Reporting (depends on everything)
  'report': {
    name: 'report',
    displayName: 'Report agent',
    prerequisites: ['sqli', 'cmdi', 'auth-attack', 'kerberoast', 'bruteforce', 'lateral', 'privesc'],
    promptTemplate: 'report',
    deliverableFilename: 'pentest_report.md',
    modelTier: 'small',
  },

});

// Execution order respecting the DAG
// Groups of agents that can run in parallel
export const EXECUTION_PHASES: AgentName[][] = [
  ['recon'],                                    // Phase 1: sequential
  ['sqli', 'cmdi', 'auth-attack'],              // Phase 2: web attacks (3 concurrent, staggered)
  ['kerberoast', 'bruteforce'],                 // Phase 3: credential attacks (2 concurrent, staggered)
  ['lateral'],                                  // Phase 4: sequential
  ['privesc'],                                  // Phase 5: sequential
  ['report'],                                   // Phase 6: sequential
];

// v2.1 F1: Dynamic phase selection based on engagement type
// For external mode, prepend Phase 0 (osint-recon) before the standard phases.
// For internal/assumed-breach, return the existing phases unchanged.
export function getExecutionPhases(engagementType: EngagementType): AgentName[][] {
  if (engagementType === 'external') {
    return [
      ['osint-recon'],  // Phase 0: external OSINT / recon (runs before internal phases)
      ...EXECUTION_PHASES,
    ];
  }
  return EXECUTION_PHASES;
}

// ============================================================================
// v3: Agent Template Library -- maps template names to prompt files + defaults
// Used by the adaptive pipeline planner to select and configure agents
// ============================================================================

export interface AgentTemplate {
  promptFile: string;
  defaultTier: ModelTier;
  defaultTimeout: number;
  defaultTurnBudget: number;
  requiresPlaywright: boolean;
}

export const AGENT_TEMPLATE_LIBRARY: Record<string, AgentTemplate> = {
  'recon':       { promptFile: 'recon',       defaultTier: 'medium', defaultTimeout: 900,  defaultTurnBudget: 100, requiresPlaywright: false },
  'osint-recon': { promptFile: 'osint-recon', defaultTier: 'medium', defaultTimeout: 600,  defaultTurnBudget: 60,  requiresPlaywright: false },
  'sqli':        { promptFile: 'sqli',        defaultTier: 'medium', defaultTimeout: 600,  defaultTurnBudget: 80,  requiresPlaywright: false },  // v3.1.0: sqlmap, no Playwright
  'cmdi':        { promptFile: 'cmdi',        defaultTier: 'medium', defaultTimeout: 600,  defaultTurnBudget: 80,  requiresPlaywright: false },  // v3.1.0: commix, no Playwright
  'auth-attack': { promptFile: 'auth-attack', defaultTier: 'medium', defaultTimeout: 600,  defaultTurnBudget: 80,  requiresPlaywright: true },
  'kerberoast':  { promptFile: 'kerberoast',  defaultTier: 'medium', defaultTimeout: 600,  defaultTurnBudget: 120, requiresPlaywright: false },
  'bruteforce':  { promptFile: 'bruteforce',  defaultTier: 'medium', defaultTimeout: 900,  defaultTurnBudget: 100, requiresPlaywright: false },
  'lateral':     { promptFile: 'lateral',     defaultTier: 'medium', defaultTimeout: 1200, defaultTurnBudget: 150, requiresPlaywright: false },
  'privesc':     { promptFile: 'privesc',     defaultTier: 'large',  defaultTimeout: 1200, defaultTurnBudget: 200, requiresPlaywright: false },
  'report':      { promptFile: 'report',      defaultTier: 'small',  defaultTimeout: 600,  defaultTurnBudget: 100, requiresPlaywright: false },
  'nuclei':      { promptFile: 'nuclei',      defaultTier: 'small',  defaultTimeout: 300,  defaultTurnBudget: 30,  requiresPlaywright: false },
  'pivot':       { promptFile: 'pivot',       defaultTier: 'medium', defaultTimeout: 600,  defaultTurnBudget: 80,  requiresPlaywright: false },
};
