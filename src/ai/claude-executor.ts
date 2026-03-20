// Claude Agent SDK executor for Wraith
// Uses CLAUDE_CODE_OAUTH_TOKEN (subscription auth, no API cost)
// v3: Exponential backoff for OAuth rate limiting (RUN-5 fix)

import { query } from '@anthropic-ai/claude-agent-sdk';
import { resolveModel } from './models.js';
import { withBackoff } from '../utils/backoff.js';
import type { ModelTier } from '../types/index.js';

export interface ExecutorResult {
  result: string | null;
  success: boolean;
  duration: number;
  turns?: number;
}

// v3.0.1: Handle for cancelling a running agent (BUG-7 fix)
export interface ExecutorHandle {
  promise: Promise<ExecutorResult>;
  abort: () => void;
}

class RateLimitError extends Error {
  constructor(agentName: string) {
    super(`Agent ${agentName} completed 0 turns (rate limited)`);
    this.name = 'RateLimitError';
  }
}

async function executeAgent(
  prompt: string,
  agentName: string,
  modelTier: ModelTier,
  mcpServers: Record<string, unknown>,
  maxTurns: number,
  abortController?: AbortController,
): Promise<ExecutorResult> {
  const start = Date.now();

  const sdkEnv: Record<string, string> = {
    CLAUDE_CODE_MAX_OUTPUT_TOKENS: process.env.CLAUDE_CODE_MAX_OUTPUT_TOKENS ?? '64000',
  };

  // Pass through auth tokens -- subscription or API key
  const passthrough = [
    'CLAUDE_CODE_OAUTH_TOKEN',
    'ANTHROPIC_API_KEY',
    'ANTHROPIC_SMALL_MODEL',
    'ANTHROPIC_MEDIUM_MODEL',
    'ANTHROPIC_LARGE_MODEL',
  ];
  for (const key of passthrough) {
    if (process.env[key]) sdkEnv[key] = process.env[key]!;
  }

  let resultText: string | null = null;
  let turns = 0;

  try {
    for await (const message of query({
      prompt,
      options: {
        model: resolveModel(modelTier),
        maxTurns,
        permissionMode: 'bypassPermissions',
        allowDangerouslySkipPermissions: true,
        mcpServers: mcpServers as Record<string, import('@anthropic-ai/claude-agent-sdk').McpServerConfig>,
        env: sdkEnv,
        abortController,
      },
    })) {
      turns++;
      if (message.type === 'result' && !message.is_error) {
        resultText = (message as import('@anthropic-ai/claude-agent-sdk').SDKResultSuccess).result ?? null;
      }
    }

    // 0 turns = rate limited -- throw so backoff can retry
    if (turns === 0) {
      throw new RateLimitError(agentName);
    }

    return {
      result: resultText,
      success: true,
      duration: Date.now() - start,
      turns,
    };
  } catch (err) {
    if (err instanceof RateLimitError) throw err;
    // AbortError is expected when we cancel via AbortController
    if (abortController?.signal.aborted) {
      return {
        result: null,
        success: false,
        duration: Date.now() - start,
        turns,
      };
    }
    console.error(`[${agentName}] Error:`, err);
    return {
      result: null,
      success: false,
      duration: Date.now() - start,
      turns,
    };
  }
}

export async function runAgent(
  prompt: string,
  agentName: string,
  modelTier: ModelTier = 'medium',
  mcpServers: Record<string, unknown> = {},
  maxTurns: number = 150,
  onRetry?: (attempt: number, delayMs: number) => void,
): Promise<ExecutorResult> {
  try {
    return await withBackoff(
      () => executeAgent(prompt, agentName, modelTier, mcpServers, maxTurns, undefined),
      (err) => err instanceof RateLimitError,
      {
        baseDelayMs: 15_000,
        maxDelayMs: 60_000,
        jitterMs: 5_000,
        maxRetries: 3,
        onRetry: (attempt, delay) => {
          console.log(`  [backoff] ${agentName} retry ${attempt} after ${Math.round(delay / 1000)}s`);
          onRetry?.(attempt, delay);
        },
      },
    );
  } catch (err) {
    if (err instanceof RateLimitError) {
      // All retries exhausted -- return failure
      return {
        result: null,
        success: false,
        duration: 0,
        turns: 0,
      };
    }
    throw err;
  }
}

// v3.0.1: Start an agent with an AbortController for cancellation (BUG-7 fix)
// Returns a handle with the promise + abort function so the caller can kill it on timeout.
export function startAgent(
  prompt: string,
  agentName: string,
  modelTier: ModelTier = 'medium',
  mcpServers: Record<string, unknown> = {},
  maxTurns: number = 150,
): ExecutorHandle {
  const controller = new AbortController();
  const promise = executeAgent(prompt, agentName, modelTier, mcpServers, maxTurns, controller);
  return {
    promise,
    abort: () => {
      console.log(`  [abort] ${agentName} -- killing SDK process via AbortController`);
      controller.abort();
    },
  };
}
