import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  meetsIsolationRequirement,
  ISOLATION_LEVEL_WEIGHTS,
  IsolationPolicy
} from '../../../../src/security/isolation/isolationTypes.js';

describe('IsolationPolicy Unit Tests', () => {
  it('correctly orders isolation level weights deterministically', () => {
    assert.equal(ISOLATION_LEVEL_WEIGHTS.NONE < ISOLATION_LEVEL_WEIGHTS.PROCESS, true);
    assert.equal(ISOLATION_LEVEL_WEIGHTS.PROCESS < ISOLATION_LEVEL_WEIGHTS.FILESYSTEM, true);
    assert.equal(ISOLATION_LEVEL_WEIGHTS.FILESYSTEM < ISOLATION_LEVEL_WEIGHTS.NETWORK, true);
    assert.equal(ISOLATION_LEVEL_WEIGHTS.NETWORK < ISOLATION_LEVEL_WEIGHTS.CONTAINER, true);
    assert.equal(ISOLATION_LEVEL_WEIGHTS.CONTAINER < ISOLATION_LEVEL_WEIGHTS.FULL, true);
  });

  it('correctly evaluates meetsIsolationRequirement for equal or stronger levels', () => {
    assert.equal(meetsIsolationRequirement('CONTAINER', 'CONTAINER'), true);
    assert.equal(meetsIsolationRequirement('FULL', 'CONTAINER'), true);
    assert.equal(meetsIsolationRequirement('CONTAINER', 'PROCESS'), true);
  });

  it('rejects weaker isolation levels when stronger level is required', () => {
    assert.equal(meetsIsolationRequirement('PROCESS', 'CONTAINER'), false);
    assert.equal(meetsIsolationRequirement('PROCESS', 'NETWORK'), false);
    assert.equal(meetsIsolationRequirement('NONE', 'PROCESS'), false);
    assert.equal(meetsIsolationRequirement('FILESYSTEM', 'CONTAINER'), false);
  });
});
