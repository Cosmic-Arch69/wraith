import type { ModelTier } from '../types/index.js';

const MODEL_DEFAULTS: Record<ModelTier, string> = {
  small: 'claude-haiku-4-5-20251001',
  medium: 'claude-sonnet-4-6',
  large: 'claude-opus-4-6',
};

export function resolveModel(tier: ModelTier): string {
  const envKey = `ANTHROPIC_${tier.toUpperCase()}_MODEL`;
  return process.env[envKey] ?? MODEL_DEFAULTS[tier];
}
