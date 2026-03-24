import { create } from "zustand";
import type {
  GraphData,
  Round,
  Credential,
  AttackStats,
  EngagementStatus,
  AttackResult,
  MitreHeatmap,
  AgentOutput,
} from "@/lib/types";

// -----------------------------------------------------------------------
// Store shape
// -----------------------------------------------------------------------

interface EngagementState {
  // Connection
  sseConnected: boolean;

  // Engagement metadata
  engagementStatus: EngagementStatus | null;

  // Graph
  graph: GraphData | null;

  // Rounds
  rounds: Round[];

  // Credentials
  credentials: Credential[];

  // Recent attacks (rolling buffer, last 200)
  recentAttacks: AttackResult[];

  // Aggregate stats (recalculated on attack updates)
  attackStats: AttackStats;

  // MITRE heatmap
  mitreHeatmap: MitreHeatmap | null;

  // Agent outputs (keyed agentId:roundId)
  agentOutputs: Record<string, AgentOutput>;

  // -----------------------------------------------------------------------
  // Actions
  // -----------------------------------------------------------------------

  setSseConnected: (connected: boolean) => void;

  setEngagementStatus: (status: EngagementStatus) => void;

  setGraph: (graph: GraphData) => void;

  setRounds: (rounds: Round[]) => void;
  appendRound: (round: Round) => void;

  setCredentials: (credentials: Credential[]) => void;
  appendCredential: (credential: Credential) => void;

  appendAttack: (attack: AttackResult) => void;
  setRecentAttacks: (attacks: AttackResult[]) => void;

  setMitreHeatmap: (heatmap: MitreHeatmap) => void;

  setAgentOutput: (output: AgentOutput) => void;

  reset: () => void;
}

// -----------------------------------------------------------------------
// Initial values
// -----------------------------------------------------------------------

const initialAttackStats: AttackStats = {
  total: 0,
  success: 0,
  failure: 0,
  partial: 0,
  successRate: 0,
};

function calculateStats(attacks: AttackResult[]): AttackStats {
  const total = attacks.length;
  const success = attacks.filter((a) => a.status === "success").length;
  const failure = attacks.filter((a) => a.status === "failure").length;
  const partial = attacks.filter((a) => a.status === "partial").length;
  const successRate = total > 0 ? Math.round((success / total) * 100) : 0;
  return { total, success, failure, partial, successRate };
}

const ATTACK_BUFFER_SIZE = 200;

// -----------------------------------------------------------------------
// Store
// -----------------------------------------------------------------------

export const useEngagementStore = create<EngagementState>((set) => ({
  sseConnected: false,
  engagementStatus: null,
  graph: null,
  rounds: [],
  credentials: [],
  recentAttacks: [],
  attackStats: initialAttackStats,
  mitreHeatmap: null,
  agentOutputs: {},

  // Connection
  setSseConnected: (connected) => set({ sseConnected: connected }),

  // Status
  setEngagementStatus: (status) => set({ engagementStatus: status }),

  // Graph
  setGraph: (graph) => set({ graph }),

  // Rounds
  setRounds: (rounds) => set({ rounds }),
  appendRound: (round) =>
    set((state) => {
      const exists = state.rounds.find((r) => r.id === round.id);
      if (exists) {
        return { rounds: state.rounds.map((r) => (r.id === round.id ? round : r)) };
      }
      return { rounds: [...state.rounds, round] };
    }),

  // Credentials
  setCredentials: (credentials) => set({ credentials }),
  appendCredential: (credential) =>
    set((state) => {
      const exists = state.credentials.find((c) => c.id === credential.id);
      if (exists) return {};
      return { credentials: [...state.credentials, credential] };
    }),

  // Attacks
  setRecentAttacks: (attacks) =>
    set({ recentAttacks: attacks, attackStats: calculateStats(attacks) }),

  appendAttack: (attack) =>
    set((state) => {
      const updated = [...state.recentAttacks, attack].slice(-ATTACK_BUFFER_SIZE);
      return {
        recentAttacks: updated,
        attackStats: calculateStats(updated),
      };
    }),

  // MITRE
  setMitreHeatmap: (heatmap) => set({ mitreHeatmap: heatmap }),

  // Agent outputs
  setAgentOutput: (output) =>
    set((state) => ({
      agentOutputs: {
        ...state.agentOutputs,
        [`${output.agentId}:${output.roundId}`]: output,
      },
    })),

  // Full reset
  reset: () =>
    set({
      sseConnected: false,
      engagementStatus: null,
      graph: null,
      rounds: [],
      credentials: [],
      recentAttacks: [],
      attackStats: initialAttackStats,
      mitreHeatmap: null,
      agentOutputs: {},
    }),
}));
