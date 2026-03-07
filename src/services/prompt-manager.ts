// Prompt template loader with variable substitution

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const PROMPTS_DIR = process.env.WRAITH_PROMPTS_DIR ?? './prompts';

export async function loadPrompt(
  templateName: string,
  vars: Record<string, string>
): Promise<string> {
  const filePath = join(PROMPTS_DIR, `${templateName}.md`);
  let content = readFileSync(filePath, 'utf-8');

  for (const [key, value] of Object.entries(vars)) {
    content = content.replaceAll(`{{${key}}}`, value);
  }

  return content;
}
