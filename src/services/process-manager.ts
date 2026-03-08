// Singleton process manager for Wraith
// Tracks spawned child processes and kills known attack tools on exit

import { execSync } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';

class ProcessManager {
  private children: Set<ChildProcess> = new Set();

  register(child: ChildProcess): void {
    this.children.add(child);
    child.on('exit', () => this.children.delete(child));
  }

  killAll(): void {
    // Kill tracked child processes
    for (const child of this.children) {
      try {
        child.kill('SIGTERM');
      } catch {
        // Process already dead -- ignore
      }
    }
    this.children.clear();

    // Kill known attack tools that may have been spawned outside tracking
    const tools = ['john', 'hashcat', 'bloodhound-python'];
    for (const tool of tools) {
      try {
        execSync(`pkill -f ${tool}`, { stdio: 'ignore' });
      } catch {
        // pkill returns non-zero if no process matched -- ignore
      }
    }
  }

  installSignalHandlers(): void {
    const cleanup = (): void => {
      this.killAll();
    };

    process.on('exit', cleanup);
    process.on('SIGINT', () => {
      cleanup();
      process.exit(130);
    });
    process.on('SIGTERM', () => {
      cleanup();
      process.exit(143);
    });
    process.on('uncaughtException', (err: Error) => {
      console.error('[wraith] Uncaught exception:', err.message);
      cleanup();
      process.exit(1);
    });
  }
}

export const processManager = new ProcessManager();
