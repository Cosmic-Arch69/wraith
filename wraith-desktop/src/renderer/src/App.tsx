import { useEffect } from 'react'
import { HashRouter, Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/layout/sidebar'
import { Header } from './components/layout/header'
import { usePipelineStore } from './stores/pipeline-store'
import { useWraithSse } from './hooks/use-wraith-sse'
import DashboardPage from './pages/dashboard'
import GraphPage from './pages/graph'
import AgentsPage from './pages/agents'
import TimelinePage from './pages/timeline'
import MitrePage from './pages/mitre'
import CredentialsPage from './pages/credentials'
import FindingsPage from './pages/findings'
import ReportPage from './pages/report'
import LaunchPage from './pages/launch'
import LogsPage from './pages/logs'
import OntologyPage from './pages/ontology'
import { SimulationMonitor } from './components/layout/simulation-monitor'
import type { PipelineEvent } from '../../shared/ipc-types'

// Top-level component that wires pipeline IPC events to the Zustand store
function PipelineEventBridge(): null {
  useEffect(() => {
    if (!window.wraithAPI) return

    const unsubscribe = window.wraithAPI.onPipelineEvent((event: PipelineEvent) => {
      const store = usePipelineStore.getState()

      switch (event.type) {
        case 'stdout':
          store.appendLog(event.data)
          break
        case 'stderr':
          store.appendLog(`[stderr] ${event.data}`)
          break
        case 'server-ready':
          store.setRunState('running')
          break
        case 'exit': {
          const code = parseInt(event.data.replace('Exited with code ', ''), 10)
          store.setRunState(code === 0 ? 'complete' : 'error')
          if (code !== 0) store.setError(`Pipeline exited with code ${code}`)
          break
        }
        case 'error':
          store.setError(event.data)
          store.setRunState('error')
          break
      }
    })

    return unsubscribe
  }, [])

  return null
}

// SSE bridge -- connects to Express server when pipeline is running
function SseBridge(): null {
  useWraithSse()
  return null
}

function App(): React.JSX.Element {
  return (
    <HashRouter>
      <PipelineEventBridge />
      <SseBridge />
      <div className="h-screen flex bg-background text-foreground overflow-hidden">
        <Sidebar />
        <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
          <Header />
          <main className="flex-1 overflow-auto scrollbar-thin p-6">
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/launch" element={<LaunchPage />} />
              <Route path="/graph" element={<GraphPage />} />
              <Route path="/agents" element={<AgentsPage />} />
              <Route path="/timeline" element={<TimelinePage />} />
              <Route path="/mitre" element={<MitrePage />} />
              <Route path="/credentials" element={<CredentialsPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/report" element={<ReportPage />} />
              <Route path="/logs" element={<LogsPage />} />
              <Route path="/ontology" element={<OntologyPage />} />
            </Routes>
          </main>
          <SimulationMonitor />
        </div>
      </div>
    </HashRouter>
  )
}

export default App
