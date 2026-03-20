// Prompt template loader with variable substitution
// v3: Added listTemplates() and loadPromptWithProfile()

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { AgentProfile } from '../types/index.js';

const PROMPTS_DIR = process.env.WRAITH_PROMPTS_DIR ?? './prompts';

export async function loadPrompt(
  templateName: string,
  vars: Record<string, string>,
): Promise<string> {
  const filePath = join(PROMPTS_DIR, `${templateName}.md`);
  let content = readFileSync(filePath, 'utf-8');

  for (const [key, value] of Object.entries(vars)) {
    content = content.replaceAll(`{{${key}}}`, value);
  }

  return content;
}

// v3: List all available prompt template names
export function listTemplates(): string[] {
  return readdirSync(PROMPTS_DIR)
    .filter(f => f.endsWith('.md'))
    .map(f => f.replace('.md', ''));
}

// v3: Load a prompt and inject AgentProfile context_vars + agent metadata
export async function loadPromptWithProfile(
  templateName: string,
  profile: AgentProfile,
  baseVars: Record<string, string>,
): Promise<string> {
  const vars: Record<string, string> = {
    ...baseVars,
    agent_id: profile.id,
    technique: profile.technique,
    technique_name: profile.technique_name,
    target_ip: profile.target_ip,
    target_service: profile.target_service ?? '',
    stealth_level: profile.stealth_level,
    round_context: profile.context_vars.round_context ?? '',
    ...profile.context_vars,
  };

  return loadPrompt(templateName, vars);
}
