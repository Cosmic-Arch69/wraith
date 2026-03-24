import { Link } from 'react-router-dom'
import { useEngagementStore } from '@/stores/engagement-store'
import { usePipelineStore } from '@/stores/pipeline-store'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'
import { Play, Square, Loader2, CheckCircle2, AlertCircle } from 'lucide-react'

function ElapsedTime({ startTime }: { startTime: string | null }): React.JSX.Element {
  if (!startTime) return <span className="text-muted-foreground">--:--:--</span>

  const start = new Date(startTime).getTime()
  const now = Date.now()
  const elapsed = Math.floor((now - start) / 1000)
  const h = String(Math.floor(elapsed / 3600)).padStart(2, '0')
  const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0')
  const s = String(elapsed % 60).padStart(2, '0')

  return (
    <span className="font-mono text-sm tabular-nums text-foreground">
      {h}:{m}:{s}
    </span>
  )
}

const phaseColors: Record<string, string> = {
  recon: 'bg-blue-100 text-blue-700 border-blue-200',
  attack: 'bg-red-100 text-red-700 border-red-200',
  reporting: 'bg-amber-100 text-amber-700 border-amber-200',
  complete: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  idle: 'bg-zinc-100 text-zinc-500 border-zinc-200',
}

const runStateConfig: Record<string, { icon: React.ReactNode; label: string; color: string }> = {
  idle: { icon: null, label: 'No active engagement', color: 'text-zinc-400' },
  starting: { icon: <Loader2 className="w-3 h-3 animate-spin" />, label: 'Starting...', color: 'text-amber-600' },
  running: { icon: <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />, label: 'Running', color: 'text-emerald-600' },
  stopping: { icon: <Loader2 className="w-3 h-3 animate-spin" />, label: 'Stopping...', color: 'text-amber-600' },
  complete: { icon: <CheckCircle2 className="w-3 h-3" />, label: 'Complete', color: 'text-emerald-600' },
  error: { icon: <AlertCircle className="w-3 h-3" />, label: 'Error', color: 'text-red-600' },
}

export function Header(): React.JSX.Element {
  const engagementStatus = useEngagementStore((s) => s.engagementStatus)
  const sseConnected = useEngagementStore((s) => s.sseConnected)
  const runState = usePipelineStore((s) => s.runState)
  const startedAt = usePipelineStore((s) => s.startedAt)

  const phase = engagementStatus?.phase ?? 'idle'
  const phaseClass = phaseColors[phase] ?? phaseColors.idle
  const stateConfig = runStateConfig[runState] ?? runStateConfig.idle

  const handleStop = (): void => {
    window.wraithAPI.stop()
  }

  return (
    <header className="h-12 shrink-0 flex items-center gap-4 px-6 border-b border-border bg-background">
      {/* Title */}
      <span className="text-sm font-semibold tracking-wider uppercase text-foreground">
        Wraith
      </span>

      <Separator orientation="vertical" className="h-5" />

      {/* Pipeline state */}
      <div className={cn('flex items-center gap-2 text-xs', stateConfig.color)}>
        {stateConfig.icon}
        <span>{stateConfig.label}</span>
      </div>

      {/* Stop button (only when running) */}
      {(runState === 'running' || runState === 'starting') && (
        <Button
          variant="outline"
          size="sm"
          onClick={handleStop}
          className="h-6 px-2 text-xs text-red-600 border-red-200 hover:bg-red-50"
        >
          <Square className="w-3 h-3 mr-1" />
          Stop
        </Button>
      )}

      {/* New engagement button (when idle/complete/error) */}
      {(runState === 'idle' || runState === 'complete' || runState === 'error') && (
        <Link to="/launch">
          <Button variant="outline" size="sm" className="h-6 px-2 text-xs">
            <Play className="w-3 h-3 mr-1" />
            New
          </Button>
        </Link>
      )}

      <Separator orientation="vertical" className="h-5" />

      {/* SSE connection dot */}
      <div className="flex items-center gap-1.5">
        <div
          className={cn(
            'w-1.5 h-1.5 rounded-full',
            sseConnected ? 'bg-emerald-500' : 'bg-zinc-300'
          )}
        />
        <span className="text-[10px] text-muted-foreground">
          {sseConnected ? 'data feed' : 'offline'}
        </span>
      </div>

      {/* Phase badge (only when running/complete) */}
      {phase !== 'idle' && (
        <>
          <Separator orientation="vertical" className="h-5" />
          <Badge
            variant="outline"
            className={cn('text-[10px] tracking-widest uppercase px-2', phaseClass)}
          >
            {phase}
          </Badge>
        </>
      )}

      {/* Elapsed time (right side) */}
      <div className="ml-auto flex items-center gap-2">
        <span className="text-[10px] text-muted-foreground">elapsed</span>
        <ElapsedTime startTime={startedAt} />
      </div>
    </header>
  )
}
