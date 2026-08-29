import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { ContainerIsolationProvider } from '../../src/security/isolation/containerProvider.js';
import { IsolationPolicy } from '../../src/security/isolation/isolationTypes.js';
import { CapabilityGrant } from '../../src/core/types.js';

describe('ContainerExecution Integration Tests', () => {
  let testWorkspace: string;
  let provider: ContainerIsolationProvider;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_cnt_integration_'));
    provider = new ContainerIsolationProvider();
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('executes process inside container sandbox if Docker is available, or gracefully skips with explicit notice', async () => {
    const isDockerAvailable = await provider.isAvailable();

    if (!isDockerAvailable) {
      console.log('ℹ️  [SKIP] ContainerIsolationProvider is unavailable on this host (Docker runtime missing or daemon unresponsive). Gracefully skipping container execution integration test.');
      assert.ok(true, 'Test gracefully skipped due to missing Docker backend.');
      return;
    }

    const policy: IsolationPolicy = {
      requiredLevel: 'CONTAINER',
      networkPolicy: { mode: 'NONE' },
      resourceLimits: { maxExecutionTimeMs: 15000, maxOutputBytes: 50000, maxMemoryMb: 256 },
      filesystemPolicy: { mode: 'RESTRICTED_WRITE', allowedWritePaths: [testWorkspace], deniedPaths: [] }
    };

    const grant: CapabilityGrant = {
      id: 'cap_cnt_test',
      operation: 'EXECUTE',
      workspaceRoot: testWorkspace,
      allowedPaths: [testWorkspace],
      deniedPaths: [],
      network: 'NONE',
      processExecution: true,
      maxExecutionTimeMs: 15000,
      maxOutputBytes: 50000,
      grantedAt: Date.now(),
      expiresAt: Date.now() + 100000,
      expectedEffects: {
        allowedPaths: [testWorkspace],
        deniedPaths: [],
        allowNetwork: false,
        allowedProcesses: ['node']
      }
    };

    const env = await provider.createEnvironment(policy, grant);
    assert.equal(env.isolationLevel, 'CONTAINER');
    assert.equal(env.isAlive(), true);

    try {
      const res = await env.execute(
        { command: 'node -v', workingDirectory: testWorkspace, purpose: 'TEST', requestedBy: 'SYSTEM' },
        { rawCommand: 'node -v', executable: 'node', args: ['-v'], env: {}, hasShellOperators: false, isDangerous: false },
        grant
      );

      assert.ok(res.stdout.startsWith('v'), 'Container node -v output should start with version');
    } finally {
      await env.destroy();
      assert.equal(env.isAlive(), false);
    }
  });
});
