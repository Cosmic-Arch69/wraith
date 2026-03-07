// Temporal workflow definitions for Wraith
// Orchestrates agent phases with crash recovery and parallel execution

import { proxyActivities } from '@temporalio/workflow';
import type { AgentName } from '../types/index.js';

const { runAgent } = proxyActivities<{
  runAgent(agentName: AgentName, configPath: string): Promise<{ success: boolean; result: string | null }>;
}>({
  startToCloseTimeout: '2 hours',
  retry: {
    maximumAttempts: 3,
    initialInterval: '30s',
    backoffCoefficient: 2,
  },
});

export async function wraithWorkflow(configPath: string): Promise<void> {
  console.log(`Starting Wraith workflow with config: ${configPath}`);

  // Phase 1: Recon (sequential)
  const recon = await runAgent('recon', configPath);
  if (!recon.success) {
    throw new Error('Recon failed -- cannot proceed');
  }

  // Phase 2+3: Web exploitation + credential attacks (parallel)
  await Promise.allSettled([
    runAgent('sqli', configPath),
    runAgent('cmdi', configPath),
    runAgent('auth-attack', configPath),
    runAgent('kerberoast', configPath),
    runAgent('bruteforce', configPath),
  ]);

  // Phase 4: Lateral movement (sequential, uses Phase 3 results)
  await runAgent('lateral', configPath);

  // Phase 5: Privilege escalation (sequential, uses Phase 4 results)
  await runAgent('privesc', configPath);

  // Phase 6: Report (sequential, compiles everything)
  await runAgent('report', configPath);

  console.log('Wraith workflow complete. Check attack-logs/ for results.');
}
