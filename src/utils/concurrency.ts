// Concurrency limiter for agent spawning
// RUN-5 fix: enforces max 3 concurrent agents across all rounds

import { staggerDelay } from './backoff.js';

export class ConcurrencyLimiter {
  private running = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly maxConcurrent: number = 3) {}

  private acquire(): Promise<void> {
    if (this.running < this.maxConcurrent) {
      this.running++;
      return Promise.resolve();
    }
    return new Promise<void>(resolve => {
      this.queue.push(() => {
        this.running++;
        resolve();
      });
    });
  }

  private release(): void {
    this.running--;
    const next = this.queue.shift();
    if (next) next();
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  async runBatch<T>(
    tasks: Array<() => Promise<T>>,
    staggerMs: number = 15_000,
    jitterMs: number = 5_000,
  ): Promise<Array<PromiseSettledResult<T>>> {
    const promises = tasks.map((task, i) =>
      this.run(async () => {
        if (i > 0) {
          const delay = staggerDelay(i, staggerMs, jitterMs);
          await new Promise(r => setTimeout(r, delay));
        }
        return task();
      }),
    );
    return Promise.allSettled(promises);
  }

  get activeCount(): number {
    return this.running;
  }

  get queueLength(): number {
    return this.queue.length;
  }
}
