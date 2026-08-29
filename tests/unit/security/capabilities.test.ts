import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CapabilityManager } from '../../../src/security/capabilities/capabilityManager.js';

describe('CapabilityManager Unit Tests', () => {
  const workspaceRoot = '/test/workspace';
  const manager = new CapabilityManager(workspaceRoot);

  it('generates a bounded CapabilityGrant with default values', () => {
    const grant = manager.generateGrant('EXECUTE', 'ALLOW');
    assert.equal(grant.operation, 'EXECUTE');
    assert.equal(grant.workspaceRoot, workspaceRoot);
    assert.equal(grant.processExecution, true);
    assert.equal(grant.network, 'NONE');
    assert.equal(grant.maxExecutionTimeMs, 60000);
    assert.equal(grant.maxOutputBytes, 100 * 1024);
  });

  it('sets processExecution to false if policyDecision is BLOCK', () => {
    const grant = manager.generateGrant('EXECUTE', 'BLOCK');
    assert.equal(grant.processExecution, false);
  });

  it('validates a valid grant successfully', () => {
    const grant = manager.generateGrant('EXECUTE', 'ALLOW');
    const check = manager.validateGrant(grant, '/test/workspace/src', 'EXECUTE');
    assert.equal(check.valid, true);
  });

  it('fails validation on workspace root mismatch', () => {
    const wrongManager = new CapabilityManager('/other/root');
    const grant = manager.generateGrant('EXECUTE', 'ALLOW');
    const check = wrongManager.validateGrant(grant, '/other/root', 'EXECUTE');
    assert.equal(check.valid, false);
    assert.ok(check.reason?.includes('workspace root mismatch'));
  });

  it('fails validation on denied path', () => {
    const grant = manager.generateGrant('EXECUTE', 'ALLOW', {
      deniedPaths: ['/test/workspace/src/secrets']
    });
    const check = manager.validateGrant(grant, '/test/workspace/src/secrets/env', 'EXECUTE');
    assert.equal(check.valid, false);
    assert.ok(check.reason?.includes('explicitly denied'));
  });

  it('fails validation on expired grant', () => {
    const expiredGrant = {
      ...manager.generateGrant('EXECUTE', 'ALLOW'),
      expiresAt: Date.now() - 1000
    };
    const check = manager.validateGrant(expiredGrant, '/test/workspace', 'EXECUTE');
    assert.equal(check.valid, false);
    assert.ok(check.reason?.includes('expired'));
  });
});
