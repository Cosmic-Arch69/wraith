// Agent registry and DAG for Wraith
// 9 agents across 6 attack phases: recon -> web+creds parallel -> lateral -> privesc -> report

import type { AgentDefinition, AgentName } from './types/index.js';

export const AGENTS: Readonly<Record<AgentName, AgentDefinition>> = Object.freeze({

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
  ['sqli', 'cmdi', 'auth-attack', 'kerberoast', 'bruteforce'],  // Phase 2+3: parallel
  ['lateral'],                                  // Phase 4: sequential
  ['privesc'],                                  // Phase 5: sequential
  ['report'],                                   // Phase 6: sequential
];
