// Wraith IPC Contract
// Shared between main process, preload, and renderer (via .d.ts)
// This is THE boundary between Electron processes.

// ---- Channel Names (typed constants, no magic strings) ----

export const IPC = {
  LAUNCH: 'wraith:launch',
  STOP: 'wraith:stop',
  STATUS: 'wraith:status',
  PIPELINE_EVENT: 'wraith:pipeline-event',
  SELECT_CONFIG: 'wraith:select-config',
} as const;

// ---- Launch Configuration ----

export interface LaunchConfig {
  /** Full YAML content -- main process writes to temp file */
  configYaml: string;
  /** Path to wraith dist/index.js */
  wraithDistPath: string;
  /** Skip pre-engagement checks */
  skipPreflight: boolean;
}

// ---- Pipeline State Machine ----

export type RunState =
  | 'idle'
  | 'starting'
  | 'running'
  | 'stopping'
  | 'complete'
  | 'error';

export interface PipelineStatus {
  state: RunState;
  pid?: number;
  port: number;
  startedAt?: string;
  error?: string;
  exitCode?: number;
}

// ---- Pipeline Events (main -> renderer) ----

export interface PipelineEvent {
  type: 'stdout' | 'stderr' | 'exit' | 'error' | 'server-ready';
  data: string;
  timestamp: string;
}

// ---- The API Surface (exposed to renderer via contextBridge) ----

export interface WraithAPI {
  /** Start the Wraith pipeline with the given config */
  launch: (config: LaunchConfig) => Promise<PipelineStatus>;
  /** Stop the running pipeline (SIGTERM, then SIGKILL after 5s) */
  stop: () => Promise<void>;
  /** Get current pipeline status */
  getStatus: () => Promise<PipelineStatus>;
  /** Subscribe to pipeline stdout/stderr/lifecycle events. Returns unsubscribe function. */
  onPipelineEvent: (cb: (event: PipelineEvent) => void) => () => void;
  /** Open native file dialog to select a YAML config file */
  selectConfigFile: () => Promise<string | null>;
  /** Current platform (darwin, linux, win32) */
  platform: string;
}
