// Simulation Monitor -- MiroFish-style bottom log panel
// Shows attack events + pipeline events in real-time, always visible at bottom
// Populates from /api/attacks on load, then appends live pipeline IPC events

import { useEffect, useRef, useState, useCallback } from 'react'
import { usePipelineStore } from '@/stores/pipeline-store'
import { ChevronUp, ChevronDown } from 'lucide-react'

const BASE_URL = 'http://localhost:3001'

interface MonitorEntry {
  time: string
  msg: string
  type: 'info' | 'success' | 'error' | 'warn' | 'phase' | 'attack' | 'cred'
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return ts.slice(0, 12)
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
  } catch {
    return '??:??:??'
  }
}

export function SimulationMonitor(): React.JSX.Element {
  const pipelineLogs = usePipelineStore((s) => s.logs)
  const runState = usePipelineStore((s) => s.runState)
  const logEndRef = useRef<HTMLDivElement>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [entries, setEntries] = useState<MonitorEntry[]>([])
  const fetchedRef = useRef(false)

  // Fetch attack events from API on mount (populates with RUN-14 data)
  const fetchAttackEvents = useCallback(async () => {
    if (fetchedRef.current) return
    try {
      const res = await fetch(`${BASE_URL}/api/attacks`, { cache: 'no-store' })
      if (!res.ok) return
      const attacks = await res.json()
      if (!Array.isArray(attacks) || attacks.length === 0) return

      fetchedRef.current = true
      const attackEntries: MonitorEntry[] = attacks.map((a: {
        timestamp?: string
        technique?: string
        techniqueName?: string
        result?: string
        status?: string
        target?: { ip?: string } | string
        tool?: string
        phase?: string
        details?: string
      }) => {
        const result = a.result || a.status || 'unknown'
        const targetIp = typeof a.target === 'string' ? a.target : a.target?.ip || '?'
        const technique = a.techniqueName || a.technique || '?'
        const tool = a.tool || '?'

        let type: MonitorEntry['type'] = 'attack'
        if (result === 'success') type = 'success'
        else if (result === 'blocked') type = 'warn'
        else if (result === 'failed') type = 'error'

        return {
          time: formatTime(a.timestamp || ''),
          msg: `[${result.toUpperCase()}] ${technique} on ${targetIp} via ${tool}${a.details ? ' -- ' + String(a.details).slice(0, 80) : ''}`,
          type,
        }
      })

      // Also fetch credentials
      try {
        const credRes = await fetch(`${BASE_URL}/api/credentials`, { cache: 'no-store' })
        if (credRes.ok) {
          const creds = await credRes.json()
          if (Array.isArray(creds)) {
            for (const c of creds) {
              attackEntries.push({
                time: formatTime(c.discovered_at || ''),
                msg: `[CREDENTIAL] ${c.username} (${c.scope}) via ${c.source} -- valid on ${(c.hosts_valid || []).join(', ')}`,
                type: 'cred',
              })
            }
          }
        }
      } catch { /* skip */ }

      // Sort by time
      attackEntries.sort((a, b) => a.time.localeCompare(b.time))
      setEntries(attackEntries)
    } catch { /* API not available yet */ }
  }, [])

  useEffect(() => {
    fetchAttackEvents()
    // Retry every 5s if API wasn't ready
    const interval = setInterval(() => {
      if (!fetchedRef.current) fetchAttackEvents()
    }, 5000)
    return () => clearInterval(interval)
  }, [fetchAttackEvents])

  // Merge pipeline logs as they come in
  const prevPipelineLen = useRef(0)
  useEffect(() => {
    if (pipelineLogs.length <= prevPipelineLen.current) return
    const newLogs = pipelineLogs.slice(prevPipelineLen.current)
    prevPipelineLen.current = pipelineLogs.length

    const newEntries: MonitorEntry[] = newLogs.map((line) => {
      let type: MonitorEntry['type'] = 'info'
      if (line.includes('[stderr]') || line.includes('ERROR')) type = 'error'
      else if (line.includes('SUCCESS') || line.includes('[done]') || line.includes('✓')) type = 'success'
      else if (line.includes('[pipeline]') || line.includes('[api]')) type = 'phase'
      else if (line.includes('WARN')) type = 'warn'

      const now = new Date()
      return {
        time: `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`,
        msg: line,
        type,
      }
    })

    setEntries((prev) => [...prev, ...newEntries].slice(-500))
  }, [pipelineLogs])

  // Auto-scroll
  useEffect(() => {
    if (logEndRef.current && !collapsed) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [entries.length, collapsed])

  const msgColors: Record<MonitorEntry['type'], string> = {
    info: '#888',
    success: '#4ade80',
    error: '#f87171',
    warn: '#fbbf24',
    phase: '#60a5fa',
    attack: '#c8cdd8',
    cred: '#a78bfa',
  }

  const isActive = runState === 'running' || runState === 'starting'

  return (
    <div
      className="shrink-0 border-t font-mono"
      style={{ backgroundColor: '#000', borderColor: '#1a1a1a' }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-1.5 cursor-pointer select-none"
        style={{ borderBottom: collapsed ? 'none' : '1px solid #1a1a1a' }}
        onClick={() => setCollapsed(!collapsed)}
      >
        <div className="flex items-center gap-3">
          <span className="text-[10px] tracking-widest" style={{ color: '#555' }}>
            SIMULATION MONITOR
          </span>
          {isActive && (
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: '#e85d3a' }} />
              <span className="text-[10px]" style={{ color: '#e85d3a' }}>LIVE</span>
            </span>
          )}
          {!isActive && entries.length > 0 && (
            <span className="text-[10px]" style={{ color: '#4ade80' }}>REPLAY</span>
          )}
          <span className="text-[10px]" style={{ color: '#333' }}>
            {entries.length} events
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px]" style={{ color: '#333' }}>
            {runState === 'idle' && entries.length > 0 ? 'RUN-14' : runState.toUpperCase()}
          </span>
          {collapsed ? (
            <ChevronUp className="w-3 h-3" style={{ color: '#444' }} />
          ) : (
            <ChevronDown className="w-3 h-3" style={{ color: '#444' }} />
          )}
        </div>
      </div>

      {/* Log content */}
      {!collapsed && (
        <div
          className="overflow-y-auto px-4 py-1"
          style={{ height: 140, scrollbarWidth: 'thin', scrollbarColor: '#222 transparent' }}
        >
          {entries.length === 0 ? (
            <div className="flex items-center justify-center h-full">
              <span className="text-[11px]" style={{ color: '#333' }}>
                Waiting for pipeline events...
              </span>
            </div>
          ) : (
            entries.map((entry, i) => (
              <div key={i} className="flex gap-3 py-0.5" style={{ fontSize: '11px', lineHeight: '1.5' }}>
                <span className="shrink-0" style={{ color: '#444', minWidth: 62 }}>
                  {entry.time}
                </span>
                <span style={{ color: msgColors[entry.type], wordBreak: 'break-all' }}>
                  {entry.msg}
                </span>
              </div>
            ))
          )}
          <div ref={logEndRef} />
        </div>
      )}
    </div>
  )
}
