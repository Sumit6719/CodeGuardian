import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { IsolationFactory } from '../../src/security/isolation/isolationFactory.js';
import { ProcessIsolationProvider } from '../../src/security/isolation/processProvider.js';
import { HostFallbackProvider } from '../../src/security/isolation/hostFallbackProvider.js';
import { IsolationPolicy } from '../../src/security/isolation/isolationTypes.js';
import { CapabilityGrant } from '../../src/core/types.js';
import { SecurityStateMachine } from '../../src/security/stateMachine/securityStateMachine.js';

describe('IsolationLifecycle Integration Tests', () => {
  let testWorkspace: string;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_isol_lifecycle_'));
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('orchestrates complete sandbox lifecycle from factory creation to process execution and destruction', async () => {
    const sm = new SecurityStateMachine('PROPOSED');
    sm.transitionTo('PARSED');
    sm.transitionTo('POLICY_CHECKED');
    sm.transitionTo('CAPABILITY_GRANTED');

    const factory = new IsolationFactory([new ProcessIsolationProvider(), new HostFallbackProvider()]);
    const policy: IsolationPolicy = {
      requiredLevel: 'PROCESS',
      networkPolicy: { mode: 'NONE' },
      resourceLimits: { maxExecutionTimeMs: 10000, maxOutputBytes: 10000 },
      filesystemPolicy: { mode: 'RESTRICTED_WRITE', allowedWritePaths: [testWorkspace], deniedPaths: [] }
    };

    const grant: CapabilityGrant = {
      id: 'cap_lifecycle_test',
      operation: 'EXECUTE',
      workspaceRoot: testWorkspace,
      allowedPaths: [testWorkspace],
      deniedPaths: [],
      network: 'NONE',
      processExecution: true,
      maxExecutionTimeMs: 10000,
      maxOutputBytes: 10000,
      grantedAt: Date.now(),
      expiresAt: Date.now() + 100000,
      expectedEffects: {
        allowedPaths: [testWorkspace],
        deniedPaths: [],
        allowNetwork: false,
        allowedProcesses: ['npm', 'npx', 'tsc']
      }
    };

    const env = await factory.createEnvironment(policy, grant);
    sm.transitionTo('ISOLATION_PREPARED');
    sm.transitionTo('ISOLATION_VERIFIED');

    assert.equal(env.isolationLevel, 'PROCESS');
    assert.equal(env.isAlive(), true);

    try {
      sm.transitionTo('PROCESS_STARTED');
      sm.transitionTo('PROCESS_RUNNING');

      // Execute legitimate echo command
      const res = await env.execute(
        { command: 'npx tsc --noEmit', workingDirectory: testWorkspace, purpose: 'TYPECHECK', requestedBy: 'SYSTEM' },
        { rawCommand: 'npx tsc --noEmit', executable: 'npx', args: ['tsc', '--noEmit'], env: {}, hasShellOperators: false, isDangerous: false },
        grant
      );

      sm.transitionTo('PROCESS_TERMINATED');
      sm.transitionTo('EFFECTS_VERIFIED');
      sm.transitionTo('COMPLETED');

      assert.ok(res !== null);
      assert.equal(sm.getCurrentState(), 'COMPLETED');
    } finally {
      await env.destroy();
      assert.equal(env.isAlive(), false);
    }
  });

  it('fails closed when required CONTAINER isolation level cannot be satisfied', async () => {
    const factory = new IsolationFactory([new ProcessIsolationProvider(), new HostFallbackProvider()]);
    const policy: IsolationPolicy = {
      requiredLevel: 'CONTAINER',
      networkPolicy: { mode: 'NONE' },
      resourceLimits: { maxExecutionTimeMs: 10000, maxOutputBytes: 10000 },
      filesystemPolicy: { mode: 'RESTRICTED_WRITE', allowedWritePaths: [testWorkspace], deniedPaths: [] }
    };

    const grant: CapabilityGrant = {
      id: 'cap_fail_test',
      operation: 'EXECUTE',
      workspaceRoot: testWorkspace,
      allowedPaths: [testWorkspace],
      deniedPaths: [],
      network: 'NONE',
      processExecution: true,
      maxExecutionTimeMs: 10000,
      maxOutputBytes: 10000,
      grantedAt: Date.now(),
      expiresAt: Date.now() + 100000,
      expectedEffects: { allowedPaths: [testWorkspace], deniedPaths: [], allowNetwork: false, allowedProcesses: [] }
    };

    await assert.rejects(
      async () => {
        await factory.createEnvironment(policy, grant);
      },
      (err: any) => {
        return err.message.includes('ISOLATION_UNSATISFIABLE');
      }
    );
  });
});
