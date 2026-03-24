import { useEffect, useRef, useCallback } from 'react'
import { getSseUrl } from '@/lib/api'
import { useEngagementStore } from '@/stores/engagement-store'
import { usePipelineStore } from '@/stores/pipeline-store'
import type {
  SseEvent,
  GraphData,
  AttackResult,
  Round,
  Credential,
  EngagementStatus,
  AgentOutput,
  MitreHeatmap,
} from '@/lib/types'

const RECONNECT_BASE_MS = 2000
const RECONNECT_MAX_MS = 30000
const RECONNECT_JITTER_MS = 500

function jitter(ms: number): number {
  return ms + Math.random() * RECONNECT_JITTER_MS
}

export function useWraithSse(): void {
  const esRef = useRef<EventSource | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectDelayRef = useRef(RECONNECT_BASE_MS)
  const mountedRef = useRef(true)

  // Gate on pipeline state -- only connect when engine is running
  const runState = usePipelineStore((s) => s.runState)
  const shouldConnect = runState === 'running'

  const engagementStore = useEngagementStore
  const pipelineStore = usePipelineStore

  const handleEvent = useCallback(
    (event: MessageEvent) => {
      let parsed: SseEvent
      try {
        parsed = JSON.parse(event.data as string) as SseEvent
      } catch {
        return
      }

      const s = engagementStore.getState()
      switch (parsed.type) {
        case 'status':
          s.setEngagementStatus(parsed.data as EngagementStatus)
          break
        case 'graph_update':
          s.setGraph(parsed.data as GraphData)
          break
        case 'attack_result':
          s.appendAttack(parsed.data as AttackResult)
          break
        case 'round_complete':
          s.appendRound(parsed.data as Round)
          break
        case 'credential_found':
          s.appendCredential(parsed.data as Credential)
          break
        case 'agent_output':
          s.setAgentOutput(parsed.data as AgentOutput)
          break
        case 'mitre_update':
          s.setMitreHeatmap(parsed.data as MitreHeatmap)
          break
        case 'heartbeat':
          break
        case 'error':
          console.error('[Wraith SSE] Server error event:', parsed.data)
          break
        default:
          break
      }
    },
    [engagementStore]
  )

  const connect = useCallback(() => {
    if (!mountedRef.current) return

    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }

    const url = getSseUrl()
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => {
      if (!mountedRef.current) return
      engagementStore.getState().setSseConnected(true)
      reconnectDelayRef.current = RECONNECT_BASE_MS
    }

    es.onmessage = handleEvent

    es.onerror = () => {
      if (!mountedRef.current) return
      engagementStore.getState().setSseConnected(false)
      es.close()
      esRef.current = null

      // Only reconnect if pipeline is still running
      const currentState = pipelineStore.getState().runState
      if (currentState !== 'running') return

      const delay = jitter(Math.min(reconnectDelayRef.current, RECONNECT_MAX_MS))
      reconnectDelayRef.current = Math.min(reconnectDelayRef.current * 2, RECONNECT_MAX_MS)

      reconnectTimerRef.current = setTimeout(() => {
        if (mountedRef.current) connect()
      }, delay)
    }
  }, [handleEvent, engagementStore, pipelineStore])

  // Connect/disconnect based on pipeline state
  useEffect(() => {
    mountedRef.current = true

    if (shouldConnect) {
      reconnectDelayRef.current = RECONNECT_BASE_MS
      connect()
    } else {
      // Disconnect when pipeline stops
      if (esRef.current) {
        esRef.current.close()
        esRef.current = null
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      engagementStore.getState().setSseConnected(false)
    }

    return () => {
      mountedRef.current = false
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
      }
      if (esRef.current) {
        esRef.current.close()
        esRef.current = null
      }
      engagementStore.getState().setSseConnected(false)
    }
  }, [shouldConnect, connect, engagementStore])
}
