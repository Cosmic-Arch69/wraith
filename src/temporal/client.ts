// Wraith Temporal client -- connects and starts workflows

import { Connection, Client } from '@temporalio/client';

export async function connectTemporal() {
  const address = process.env.TEMPORAL_ADDRESS ?? 'localhost:7233';
  const connection = await Connection.connect({ address });
  const client = new Client({ connection });
  return { client, connection };
}

export async function startWraithWorkflow(client: Client, configPath: string): Promise<string> {
  const workflowId = `wraith-${Date.now()}`;
  const handle = await client.workflow.start('wraithWorkflow', {
    taskQueue: 'wraith',
    workflowId,
    args: [configPath],
  });
  return handle.workflowId;
}

export async function getWorkflowStatus(client: Client, workflowId: string) {
  const handle = client.workflow.getHandle(workflowId);
  const desc = await handle.describe();
  return {
    workflowId: desc.workflowId,
    status: desc.status.name,
    startTime: desc.startTime,
  };
}
