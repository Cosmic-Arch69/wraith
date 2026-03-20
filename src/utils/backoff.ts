// Exponential backoff with jitter for Claude OAuth rate limiting
// RUN-5 fix: replaces fixed 12s stagger + single 30s retry

export interface BackoffOptions {
  baseDelayMs: number;
  maxDelayMs: number;
  jitterMs: number;
  maxRetries: number;
  onRetry?: (attempt: number, delayMs: number, error: unknown) => void;
}

const DEFAULTS: BackoffOptions = {
  baseDelayMs: 15_000,
  maxDelayMs: 60_000,
  jitterMs: 5_000,
  maxRetries: 3,
};

function jitter(maxMs: number): number {
  return Math.floor(Math.random() * maxMs);
}

function computeDelay(attempt: number, opts: BackoffOptions): number {
  const exponential = opts.baseDelayMs * Math.pow(2, attempt);
  const capped = Math.min(exponential, opts.maxDelayMs);
  return capped + jitter(opts.jitterMs);
}

export async function withBackoff<T>(
  fn: () => Promise<T>,
  isRetryable: (error: unknown) => boolean,
  options?: Partial<BackoffOptions>,
): Promise<T> {
  const opts = { ...DEFAULTS, ...options };

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= opts.maxRetries || !isRetryable(err)) {
        throw err;
      }
      const delay = computeDelay(attempt, opts);
      opts.onRetry?.(attempt + 1, delay, err);
      await new Promise(r => setTimeout(r, delay));
    }
  }

  // Unreachable, but satisfies TypeScript
  throw new Error('withBackoff: exhausted retries');
}

export function staggerDelay(index: number, baseMs: number = 15_000, jitterMs: number = 5_000): number {
  return index * baseMs + jitter(jitterMs);
}
