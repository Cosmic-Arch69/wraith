// Shared types for Wraith Console
// Console imports from here -- single source of truth

export type {
  AttackEvent,
  AttackGraph,
  AttackGraphNode,
  AttackOntology,
  AttackResult,
  AgentProfile,
  AgentRoundResult,
  Credential,
  CredentialScope,
  CredentialSource,
  Finding,
  FindingSeverity,
  GraphDelta,
  NotableEntity,
  OntologyEntityType,
  OntologyEdgeType,
  RoundResult,
  WraithV3Config,
} from '../types/index.js';

export type {
  AttackStats,
  DetectionMatrixEntry,
  EngagementStatus,
  MITREHeatmap,
  MITRETactic,
  MITRETechniqueEntry,
  SSEEvent,
  SSEEventType,
} from './types.js';
