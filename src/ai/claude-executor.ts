// Claude Agent SDK executor for Wraith
// Uses CLAUDE_CODE_OAUTH_TOKEN (subscription auth, no API cost)

import { query } from '@anthropic-ai/claude-agent-sdk';
import { resolveModel } from './models.js';
import type { ModelTier } from '../types/index.js';

export interface ExecutorResult {
  result: string | null;
  success: boolean;
  duration: number;
  turns?: number;
}

export async function runAgent(
  prompt: string,
  agentName: string,
  modelTier: ModelTier = 'medium',
  mcpServers: Record<string, unknown> = {},
  maxTurns: number = 150
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
      },
    })) {
      turns++;
      if (message.type === 'result' && !message.is_error) {
        // SDKResultSuccess has .result; SDKResultError does not
        resultText = (message as import('@anthropic-ai/claude-agent-sdk').SDKResultSuccess).result ?? null;
      }
    }

    return {
      result: resultText,
      success: turns > 0,  // B2: 0 turns = rate limit hit, not a real success
      duration: Date.now() - start,
      turns,
    };
  } catch (err) {
    console.error(`[${agentName}] Error:`, err);
    return {
      result: null,
      success: false,
      duration: Date.now() - start,
    };
  }
}
