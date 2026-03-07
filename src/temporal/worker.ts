// Temporal worker entrypoint

import { Worker, NativeConnection } from '@temporalio/worker';
import * as activities from './activities.js';

async function main() {
  const temporalAddress = process.env.TEMPORAL_ADDRESS ?? 'localhost:7233';
  const connection = await NativeConnection.connect({ address: temporalAddress });

  const worker = await Worker.create({
    workflowsPath: new URL('./workflows.js', import.meta.url).pathname,
    activities,
    taskQueue: 'wraith',
    connection,
  });

  console.log(`Wraith worker started -- Temporal at ${temporalAddress}`);
  await worker.run();
}

main().catch((err) => {
  console.error('Worker error:', err);
  process.exit(1);
});
