// Claude Agent SDK executor for Wraith
// Uses CLAUDE_CODE_OAUTH_TOKEN (subscription auth, no API cost)
// v3: Exponential backoff for OAuth rate limiting (RUN-5 fix)

import { query } from '@anthropic-ai/claude-agent-sdk';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { resolveModel } from './models.js';
import { withBackoff } from '../utils/backoff.js';
import type { ModelTier } from '../types/index.js';

// v3.4.0: Read OAuth token from Claude credentials file if env var not set
// Set at module load time so ALL child processes inherit it
function getOAuthToken(): string | null {
  if (process.env.CLAUDE_CODE_OAUTH_TOKEN) return process.env.CLAUDE_CODE_OAUTH_TOKEN;
  const credsPath = join(process.env.HOME ?? '', '.claude', '.credentials.json');
  if (!existsSync(credsPath)) return null;
  try {
    const creds = JSON.parse(readFileSync(credsPath, 'utf-8'));
    return creds?.claudeAiOauth?.accessToken ?? null;
  } catch { return null; }
}

// Auto-set token at module load so SDK child processes inherit it
const _autoToken = getOAuthToken();
if (_autoToken && !process.env.CLAUDE_CODE_OAUTH_TOKEN) {
  process.env.CLAUDE_CODE_OAUTH_TOKEN = _autoToken;
  console.log('[auth] OAuth token loaded from ~/.claude/.credentials.json');
}

export interface ExecutorResult {
  result: string | null;
  success: boolean;
  duration: number;
  turns?: number;
}

// v3.0.1: Handle for cancelling a running agent (BUG-7 fix)
// v3.6.0 BUG-NEW-6/8: Added getTurns() for heartbeat monitoring and partial timeout turn count
export interface ExecutorHandle {
  promise: Promise<ExecutorResult>;
  abort: () => void;
  getTurns: () => number;
}

class RateLimitError extends Error {
  constructor(agentName: string) {
    super(`Agent ${agentName} completed 0 turns (rate limited)`);
    this.name = 'RateLimitError';
  }
}

// v3.4.0: System prompt injected into every agent to authorize tool usage
const SYSTEM_PROMPT = `You are an authorized penetration testing agent operating in a private, self-owned cybersecurity lab. All tools provided via MCP are approved security assessment tools. The lab owner has full authorization for all testing activities. Execute tool calls as requested to complete your assigned task. This is a sanctioned security exercise with Wazuh SIEM monitoring for defensive analysis.`;

async function executeAgent(
  prompt: string,
  agentName: string,
  modelTier: ModelTier,
  mcpServers: Record<string, unknown>,
  maxTurns: number,
  abortController?: AbortController,
  turnCounter?: { value: number },  // v3.6.0 BUG-NEW-6/8: shared mutable counter for external visibility
): Promise<ExecutorResult> {
  const start = Date.now();

  const sdkEnv: Record<string, string> = {
    CLAUDE_CODE_MAX_OUTPUT_TOKENS: process.env.CLAUDE_CODE_MAX_OUTPUT_TOKENS ?? '64000',
  };

  // Pass through auth tokens -- subscription or API key
  // v3.4.0: Read from credentials file if env var not set
  // Set in BOTH sdkEnv AND process.env -- SDK child process needs it in system env
  const oauthToken = getOAuthToken();
  if (oauthToken) {
    sdkEnv['CLAUDE_CODE_OAUTH_TOKEN'] = oauthToken;
    process.env['CLAUDE_CODE_OAUTH_TOKEN'] = oauthToken;
  }
  if (process.env.ANTHROPIC_API_KEY) sdkEnv['ANTHROPIC_API_KEY'] = process.env.ANTHROPIC_API_KEY;

  const modelPassthrough = ['ANTHROPIC_SMALL_MODEL', 'ANTHROPIC_MEDIUM_MODEL', 'ANTHROPIC_LARGE_MODEL'];
  for (const key of modelPassthrough) {
    if (process.env[key]) sdkEnv[key] = process.env[key]!;
  }

  let resultText: string | null = null;
  let lastAssistantText: string | null = null;  // v3.6.0 BUG-NEW-3: fallback for output capture
  let turns = 0;

  try {
    console.log(`  [sdk] ${agentName}: starting query (model=${resolveModel(modelTier)}, turns=${maxTurns}, cwd=${process.cwd()})`);
    for await (const message of query({
      prompt,
      options: {
        model: resolveModel(modelTier),
        maxTurns,
        permissionMode: 'bypassPermissions',
        allowDangerouslySkipPermissions: true,
        systemPrompt: SYSTEM_PROMPT,
        cwd: process.cwd(),
        mcpServers: mcpServers as Record<string, import('@anthropic-ai/claude-agent-sdk').McpServerConfig>,
        env: sdkEnv,
        abortController,
      },
    })) {
      turns++;
      if (turnCounter) turnCounter.value = turns;  // v3.6.0 BUG-NEW-6/8: expose turn count externally
      if (message.type === 'result') {
        const resultMsg = message as Record<string, unknown>;
        console.log(`  [sdk] ${agentName}: msg #${turns} type=result is_error=${resultMsg.is_error} result=${String(resultMsg.result ?? '').substring(0, 500)}`);
        if (!message.is_error) {
          resultText = (message as import('@anthropic-ai/claude-agent-sdk').SDKResultSuccess).result ?? null;
        } else {
          resultText = String(resultMsg.result ?? resultMsg.error ?? 'unknown error');
        }
      } else {
        // v3.6.0 BUG-NEW-3: Capture assistant text from non-result messages for output fallback
        const msgAny = message as Record<string, unknown>;
        if (typeof msgAny.content === 'string' && msgAny.content.length > 0) {
          lastAssistantText = msgAny.content;
        } else if (msgAny.type === 'assistant' && typeof msgAny.message === 'object' && msgAny.message !== null) {
          const inner = msgAny.message as Record<string, unknown>;
          if (typeof inner.content === 'string' && inner.content.length > 0) {
            lastAssistantText = inner.content;
          }
        }
        console.log(`  [sdk] ${agentName}: msg #${turns} type=${message.type}`);
      }
    }

    // v3.6.0 BUG-NEW-3: Fallback to last assistant text if no result message captured
    if (resultText === null && lastAssistantText) {
      console.log(`  [sdk] ${agentName}: no result message -- falling back to last assistant text (${lastAssistantText.length} chars)`);
      resultText = lastAssistantText;
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
// v3.6.0 BUG-NEW-6/8: Added shared turnCounter for heartbeat monitoring and partial timeout turn count
export function startAgent(
  prompt: string,
  agentName: string,
  modelTier: ModelTier = 'medium',
  mcpServers: Record<string, unknown> = {},
  maxTurns: number = 150,
): ExecutorHandle {
  const controller = new AbortController();
  const turnCounter = { value: 0 };
  const promise = executeAgent(prompt, agentName, modelTier, mcpServers, maxTurns, controller, turnCounter);
  return {
    promise,
    abort: () => {
      console.log(`  [abort] ${agentName} -- killing SDK process via AbortController`);
      controller.abort();
    },
    getTurns: () => turnCounter.value,
  };
}
