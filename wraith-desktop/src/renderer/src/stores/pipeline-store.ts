import { create } from 'zustand'
import type { RunState } from '../../../shared/ipc-types'

const MAX_LOGS = 500

interface PipelineStore {
  runState: RunState
  port: number
  logs: string[]
  error: string | null
  startedAt: string | null

  setRunState: (state: RunState) => void
  appendLog: (line: string) => void
  setError: (error: string | null) => void
  setStartedAt: (ts: string | null) => void
  reset: () => void
}

export const usePipelineStore = create<PipelineStore>((set) => ({
  runState: 'idle',
  port: 3001,
  logs: [],
  error: null,
  startedAt: null,

  setRunState: (runState) => set({ runState }),
  appendLog: (line) =>
    set((state) => ({
      logs: [...state.logs, line].slice(-MAX_LOGS),
    })),
  setError: (error) => set({ error }),
  setStartedAt: (startedAt) => set({ startedAt }),
  reset: () =>
    set({
      runState: 'idle',
      logs: [],
      error: null,
      startedAt: null,
    }),
}))
