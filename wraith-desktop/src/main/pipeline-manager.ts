// Pipeline Manager -- spawns and manages the Wraith engine as a child process
// Follows the VS Code UtilityProcess pattern: main process manages lifecycle,
// forwards events to renderer. The child process is NOT the renderer.

import { spawn, type ChildProcess } from 'node:child_process'
import { writeFileSync, unlinkSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { app, type BrowserWindow } from 'electron'
import { IPC, type LaunchConfig, type PipelineStatus, type PipelineEvent, type RunState } from '../shared/ipc-types'

const API_PORT = 3001
const STOP_TIMEOUT_MS = 5000 // SIGTERM -> wait -> SIGKILL

export class PipelineManager {
  private child: ChildProcess | null = null
  private state: RunState = 'idle'
  private startedAt: string | null = null
  private error: string | null = null
  private exitCode: number | null = null
  private tempConfigPath: string | null = null
  private mainWindow: BrowserWindow | null = null

  setMainWindow(win: BrowserWindow): void {
    this.mainWindow = win
  }

  getStatus(): PipelineStatus {
    return {
      state: this.state,
      pid: this.child?.pid,
      port: API_PORT,
      startedAt: this.startedAt ?? undefined,
      error: this.error ?? undefined,
      exitCode: this.exitCode ?? undefined,
    }
  }

  async launch(config: LaunchConfig): Promise<PipelineStatus> {
    if (this.state === 'running' || this.state === 'starting') {
      return { ...this.getStatus(), error: 'Pipeline already running' }
    }

    // Reset state
    this.state = 'starting'
    this.error = null
    this.exitCode = null
    this.startedAt = new Date().toISOString()

    // Write config YAML to temp file
    const tempDir = app.getPath('temp')
    this.tempConfigPath = join(tempDir, `wraith-config-${randomUUID()}.yaml`)
    writeFileSync(this.tempConfigPath, config.configYaml, 'utf-8')

    // Build spawn args
    const args = ['run', '--config', this.tempConfigPath]
    if (config.skipPreflight) {
      args.push('--skip-preflight')
    }

    // Spawn the Wraith engine as child process
    // The engine starts its own Express server on API_PORT
    try {
      this.child = spawn('node', [config.wraithDistPath, ...args], {
        env: {
          ...process.env,
          WRAITH_API_PORT: String(API_PORT),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: false,
      })
    } catch (err) {
      this.state = 'error'
      this.error = `Failed to spawn: ${err}`
      this.emitEvent({ type: 'error', data: this.error, timestamp: new Date().toISOString() })
      return this.getStatus()
    }

    this.emitEvent({ type: 'stdout', data: `[wraith] Spawned PID ${this.child.pid}`, timestamp: new Date().toISOString() })

    // Stream stdout line-by-line
    let stdoutBuffer = ''
    this.child.stdout?.on('data', (chunk: Buffer) => {
      stdoutBuffer += chunk.toString('utf-8')
      const lines = stdoutBuffer.split('\n')
      stdoutBuffer = lines.pop() ?? '' // keep incomplete line in buffer

      for (const line of lines) {
        if (!line.trim()) continue

        // Detect API server ready
        if (line.includes('[api] Console API server on http://')) {
          this.state = 'running'
          this.emitEvent({ type: 'server-ready', data: `http://localhost:${API_PORT}`, timestamp: new Date().toISOString() })
        }

        this.emitEvent({ type: 'stdout', data: line, timestamp: new Date().toISOString() })
      }
    })

    // Stream stderr
    let stderrBuffer = ''
    this.child.stderr?.on('data', (chunk: Buffer) => {
      stderrBuffer += chunk.toString('utf-8')
      const lines = stderrBuffer.split('\n')
      stderrBuffer = lines.pop() ?? ''

      for (const line of lines) {
        if (!line.trim()) continue
        this.emitEvent({ type: 'stderr', data: line, timestamp: new Date().toISOString() })
      }
    })

    // Handle process exit
    this.child.on('close', (code) => {
      this.exitCode = code
      if (this.state === 'stopping') {
        this.state = 'idle'
      } else if (code === 0) {
        this.state = 'complete'
      } else {
        this.state = 'error'
        this.error = `Process exited with code ${code}`
      }

      this.emitEvent({
        type: 'exit',
        data: `Exited with code ${code}`,
        timestamp: new Date().toISOString(),
      })

      this.child = null
      this.cleanup()
    })

    this.child.on('error', (err) => {
      this.state = 'error'
      this.error = err.message
      this.emitEvent({ type: 'error', data: err.message, timestamp: new Date().toISOString() })
      this.child = null
      this.cleanup()
    })

    return this.getStatus()
  }

  async stop(): Promise<void> {
    if (!this.child || this.state === 'idle' || this.state === 'stopping') {
      return
    }

    this.state = 'stopping'
    this.emitEvent({ type: 'stdout', data: '[wraith] Stopping pipeline...', timestamp: new Date().toISOString() })

    // SIGTERM first
    this.child.kill('SIGTERM')

    // If still alive after timeout, SIGKILL
    const pid = this.child.pid
    setTimeout(() => {
      if (this.child && this.child.pid === pid) {
        this.child.kill('SIGKILL')
        this.emitEvent({ type: 'stdout', data: '[wraith] Force killed (SIGKILL)', timestamp: new Date().toISOString() })
      }
    }, STOP_TIMEOUT_MS)
  }

  private emitEvent(event: PipelineEvent): void {
    if (this.mainWindow && !this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send(IPC.PIPELINE_EVENT, event)
    }
  }

  private cleanup(): void {
    if (this.tempConfigPath && existsSync(this.tempConfigPath)) {
      try {
        unlinkSync(this.tempConfigPath)
      } catch {
        // non-critical
      }
      this.tempConfigPath = null
    }
  }
}
