import { useEffect, useRef } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { usePipelineStore } from '@/stores/pipeline-store'
import { Terminal, Trash2 } from 'lucide-react'

export default function LogsPage(): React.JSX.Element {
  const logs = usePipelineStore((s) => s.logs)
  const runState = usePipelineStore((s) => s.runState)
  const scrollRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom on new logs
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [logs.length])

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Terminal className="w-5 h-5 text-zinc-500" />
          <h1 className="text-lg font-semibold">Pipeline Logs</h1>
          <Badge variant="outline" className="text-xs">
            {logs.length} lines
          </Badge>
          {runState === 'running' && (
            <Badge className="bg-emerald-100 text-emerald-700 border-emerald-200 text-xs">
              Live
            </Badge>
          )}
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => usePipelineStore.getState().reset()}
          className="text-xs"
        >
          <Trash2 className="w-3 h-3 mr-1" />
          Clear
        </Button>
      </div>

      {/* Log viewer */}
      <Card className="flex-1 min-h-0">
        <CardContent className="p-0 h-full">
          <div
            ref={scrollRef}
            className="h-full overflow-auto p-4 font-mono text-xs leading-relaxed bg-zinc-950 text-zinc-300 rounded-lg"
          >
            {logs.length === 0 ? (
              <div className="flex items-center justify-center h-full text-zinc-600">
                <p>No logs yet. Launch an engagement to see pipeline output.</p>
              </div>
            ) : (
              logs.map((line, i) => {
                const isError = line.startsWith('[stderr]') || line.includes('ERROR') || line.includes('Error')
                const isWarn = line.includes('WARN') || line.includes('[warn]')
                const isSuccess = line.includes('SUCCESS') || line.includes('[done]')
                const isPhase = line.includes('[pipeline]')
                const isApi = line.includes('[api]')

                return (
                  <div
                    key={i}
                    className={`py-0.5 ${
                      isError
                        ? 'text-red-400'
                        : isWarn
                          ? 'text-amber-400'
                          : isSuccess
                            ? 'text-emerald-400'
                            : isPhase
                              ? 'text-blue-400 font-semibold'
                              : isApi
                                ? 'text-purple-400'
                                : 'text-zinc-300'
                    }`}
                  >
                    <span className="text-zinc-600 select-none mr-3">
                      {String(i + 1).padStart(4, ' ')}
                    </span>
                    {line}
                  </div>
                )
              })
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
