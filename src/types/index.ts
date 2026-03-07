// Core type definitions for Wraith

export type AgentName =
  | 'recon'
  | 'sqli'
  | 'cmdi'
  | 'auth-attack'
  | 'kerberoast'
  | 'bruteforce'
  | 'lateral'
  | 'privesc'
  | 'report';

export type ModelTier = 'small' | 'medium' | 'large';

export type AttackResult = 'success' | 'failed' | 'blocked' | 'skipped';

export interface AgentDefinition {
  name: AgentName;
  displayName: string;
  prerequisites: AgentName[];
  promptTemplate: string;
  deliverableFilename: string;
  modelTier?: ModelTier;
  usePlaywright?: boolean;
}

export interface AttackEvent {
  timestamp: string;
  phase: string;
  technique: string;
  techniqueName: string;
  target: {
    ip: string;
    user?: string;
    service?: string;
    url?: string;
  };
  sourceIp: string;
  tool: string;
  result: AttackResult;
  wazuhRuleExpected: string;
  details: string;
}

export interface WraithConfig {
  target: {
    domain: string;
    dc: string;
    hosts: Array<{
      ip: string;
      name: string;
      web_url?: string;
      web_app?: string;
    }>;
    credentials: {
      domain_user: string;
      domain_pass: string;
      web_dvwa_user?: string;
      web_dvwa_pass?: string;
    };
  };
  attack: {
    randomize: boolean;
    delay_min_sec: number;
    delay_max_sec: number;
    phases: number[];
  };
  output: {
    log_dir: string;
    report: boolean;
  };
}
