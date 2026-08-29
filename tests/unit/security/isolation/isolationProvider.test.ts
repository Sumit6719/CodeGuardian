import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { IsolationFactory } from '../../../../src/security/isolation/isolationFactory.js';
import { ProcessIsolationProvider } from '../../../../src/security/isolation/processProvider.js';
import { HostFallbackProvider } from '../../../../src/security/isolation/hostFallbackProvider.js';
import { IsolationPolicy } from '../../../../src/security/isolation/isolationTypes.js';
import { CapabilityGrant } from '../../../../src/core/types.js';

describe('IsolationProvider & IsolationFactory Unit Tests', () => {
  const workspaceRoot = '/test/workspace';
  const basePolicy: IsolationPolicy = {
    requiredLevel: 'PROCESS',
    networkPolicy: { mode: 'NONE' },
    resourceLimits: { maxExecutionTimeMs: 10000, maxOutputBytes: 10000 },
    filesystemPolicy: { mode: 'RESTRICTED_WRITE', allowedWritePaths: [workspaceRoot], deniedPaths: [] }
  };

  const baseGrant: CapabilityGrant = {
    id: 'cap_test',
    operation: 'EXECUTE',
    workspaceRoot,
    allowedPaths: [workspaceRoot],
    deniedPaths: [],
    network: 'NONE',
    processExecution: true,
    maxExecutionTimeMs: 10000,
    maxOutputBytes: 10000,
    grantedAt: Date.now(),
    expiresAt: Date.now() + 100000,
    expectedEffects: {
      allowedPaths: [workspaceRoot],
      deniedPaths: [],
      allowNetwork: false,
      allowedProcesses: []
    }
  };

  it('HostFallbackProvider reports PROCESS level only', async () => {
    const provider = new HostFallbackProvider();
    assert.equal(provider.isolationLevel, 'PROCESS');
    assert.equal(await provider.isAvailable(), true);
  });

  it('IsolationFactory selects available PROCESS provider when PROCESS is requested', async () => {
    const factory = new IsolationFactory([new ProcessIsolationProvider(), new HostFallbackProvider()]);
    const selected = await factory.selectProvider(basePolicy);

    assert.ok(selected !== null);
    assert.equal(selected!.isolationLevel, 'PROCESS');
  });

  it('IsolationFactory fails closed (returns NULL) when CONTAINER is required but unavailable', async () => {
    // Register only PROCESS and HOST fallback providers
    const factory = new IsolationFactory([new ProcessIsolationProvider(), new HostFallbackProvider()]);
    const containerPolicy: IsolationPolicy = {
      ...basePolicy,
      requiredLevel: 'CONTAINER'
    };

    const selected = await factory.selectProvider(containerPolicy);
    assert.equal(selected, null, 'Factory MUST fail closed and return null when required isolation cannot be satisfied.');
  });

  it('IsolationFactory createEnvironment throws ISOLATION_UNSATISFIABLE when requirement cannot be met', async () => {
    const factory = new IsolationFactory([new HostFallbackProvider()]);
    const containerPolicy: IsolationPolicy = {
      ...basePolicy,
      requiredLevel: 'CONTAINER'
    };

    await assert.rejects(
      async () => {
        await factory.createEnvironment(containerPolicy, baseGrant);
      },
      (err: any) => {
        return err.message.includes('ISOLATION_UNSATISFIABLE') && err.message.includes('CONTAINER');
      }
    );
  });
});
