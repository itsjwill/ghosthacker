/**
 * Enhanced Worker - Registers both standard and adversarial workflows
 */

import { Worker, NativeConnection } from '@temporalio/worker';
import * as activities from './activities.js';
import { enhancedActivities } from './enhanced-activities.js';

async function run() {
  const connection = await NativeConnection.connect({
    address: process.env.TEMPORAL_ADDRESS || 'localhost:7233',
  });

  const worker = await Worker.create({
    connection,
    namespace: 'default',
    taskQueue: 'ghosthacker-enhanced',
    workflowsPath: new URL('./enhanced-workflow.js', import.meta.url).pathname,
    activities: {
      // Standard activities
      ...activities,
      // Enhanced activities
      ...enhancedActivities,
    },
    maxConcurrentActivityTaskExecutions: 10,
    maxConcurrentWorkflowTaskExecutions: 5,
  });

  console.log('🔥 Enhanced Worker started - CHAOS vs ORDER ready');
  console.log('   Task Queue: ghosthacker-enhanced');

  await worker.run();
}

run().catch((err) => {
  console.error('Worker failed:', err);
  process.exit(1);
});
