import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine } from '../../../src/permissions/policyEngine.js';
import { SessionStore } from '../../../src/permissions/sessionStore.js';
import { PolicyContext } from '../../../src/permissions/policy.interface.js';

describe('PolicyEngine Deterministic Decisions', () => {
  const engine = new PolicyEngine();

  const baseContext: PolicyContext = {
    operation: 'READ',
    targetPath: 'src/app.js',
    relativePath: 'src/app.js',
    isWorkspaceContained: true,
    sensitivity: 'MEDIUM',
    blastRadius: 'LOCAL',
    risk: { level: 'LOW', score: 15, factors: [] }
  };

  it('allows safe read of normal workspace source files', () => {
    const decision = engine.evaluate(baseContext);
    assert.equal(decision.decision, 'ALLOW');
    assert.equal(decision.requiresUserConfirmation, false);
  });

  it('requires user confirmation for modifying workspace files (ASK_USER)', () => {
    const decision = engine.evaluate({
      ...baseContext,
      operation: 'WRITE',
      risk: { level: 'MEDIUM', score: 45, factors: [] }
    });
    assert.equal(decision.decision, 'ASK_USER');
    assert.equal(decision.requiresUserConfirmation, true);
  });

  it('requires user confirmation for deleting files (ASK_USER)', () => {
    const decision = engine.evaluate({
      ...baseContext,
      operation: 'DELETE',
      risk: { level: 'HIGH', score: 70, factors: [] }
    });
    assert.equal(decision.decision, 'ASK_USER');
    assert.equal(decision.requiresUserConfirmation, true);
  });

  it('blocks modifying CRITICAL sensitive assets (.env / secrets)', () => {
    const decision = engine.evaluate({
      ...baseContext,
      operation: 'WRITE',
      targetPath: '.env',
      relativePath: '.env',
      sensitivity: 'CRITICAL',
      risk: { level: 'CRITICAL', score: 95, factors: [] }
    });
    assert.equal(decision.decision, 'BLOCK');
    assert.match(decision.reason, /CRITICAL sensitivity/i);
  });

  it('blocks reading CRITICAL sensitive assets into LLM context', () => {
    const decision = engine.evaluate({
      ...baseContext,
      operation: 'READ',
      targetPath: '.env',
      relativePath: '.env',
      sensitivity: 'CRITICAL',
      risk: { level: 'HIGH', score: 65, factors: [] }
    });
    assert.equal(decision.decision, 'BLOCK');
  });

  it('blocks operations outside the workspace', () => {
    const decision = engine.evaluate({
      ...baseContext,
      isWorkspaceContained: false,
      targetPath: '../../etc/shadow',
      relativePath: '',
      risk: { level: 'CRITICAL', score: 100, factors: [] }
    });
    assert.equal(decision.decision, 'BLOCK');
    assert.match(decision.reason, /escapes workspace/i);
  });

  it('blocks unknown operations (fail closed)', () => {
    const decision = engine.evaluate({
      ...baseContext,
      operation: 'UNKNOWN',
      risk: { level: 'CRITICAL', score: 90, factors: [] }
    });
    assert.equal(decision.decision, 'BLOCK');
    assert.match(decision.reason, /unknown/i);
  });

  it('respects session-level permission grants for ASK_USER actions', () => {
    const sessionStore = new SessionStore();
    const sessionEngine = new PolicyEngine(undefined, sessionStore);

    const writeContext: PolicyContext = {
      ...baseContext,
      operation: 'WRITE',
      targetPath: 'src/cache.js',
      relativePath: 'src/cache.js',
      risk: { level: 'MEDIUM', score: 45, factors: [] }
    };

    // First time: ASK_USER
    const firstDecision = sessionEngine.evaluate(writeContext);
    assert.equal(firstDecision.decision, 'ASK_USER');

    // Grant session approval
    sessionStore.grant('WRITE', 'src/cache.js');

    // Second time: ALLOW
    const secondDecision = sessionEngine.evaluate(writeContext);
    assert.equal(secondDecision.decision, 'ALLOW');
    assert.equal(secondDecision.requiresUserConfirmation, false);
    assert.match(secondDecision.matchedRule, /SESSION_APPROVED/);
  });
});
