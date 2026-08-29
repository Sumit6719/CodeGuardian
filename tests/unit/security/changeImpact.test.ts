import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ChangeImpactIntelligence } from '../../../src/security/effects/changeImpact.js';
import { ObservedEffects } from '../../../src/security/effects/effectTypes.js';

describe('ChangeImpactIntelligence Unit Tests', () => {
  const workspaceRoot = '/test/workspace';
  const intel = new ChangeImpactIntelligence(workspaceRoot);

  it('reports zero changes when ObservedEffects filesystem is empty', () => {
    const observed: ObservedEffects = {
      filesystem: [],
      network: [],
      processes: []
    };

    const impact = intel.calculate(observed, 10);
    assert.equal(impact.score, 0);
    assert.equal(impact.severity, 'LOW');
    assert.equal(impact.filesCreated, 0);
    assert.equal(impact.filesChanged, 0);
    assert.equal(impact.filesDeleted, 0);
  });

  it('calculates deterministic scores based on modifications and critical paths', () => {
    const observed: ObservedEffects = {
      filesystem: [
        {
          type: 'FILE_CREATE',
          target: `${workspaceRoot}/src/app.ts`,
          timestamp: Date.now()
        },
        {
          type: 'FILE_WRITE',
          target: `${workspaceRoot}/package.json`, // critical file path
          timestamp: Date.now()
        }
      ],
      network: [],
      processes: []
    };

    const impact = intel.calculate(observed, 10);
    // FILE_CREATE (10) + FILE_WRITE (5) + CRITICAL_PATH (50) + high percent (>25% of 10 is 20%? Wait, 2/10 = 20%, so not > 25%.)
    // Unexpected path bonus: src/app.ts & package.json (not dist/build/coverage) -> unexpectedEffects++ (2) -> score += 10.
    // Total score expected: 10 + 5 + 50 + 10 = 75.
    assert.equal(impact.score, 75);
    assert.equal(impact.severity, 'HIGH');
    assert.equal(impact.filesCreated, 1);
    assert.equal(impact.filesChanged, 1);
    assert.equal(impact.criticalPathsTouched, 1);
    assert.equal(impact.unexpectedEffects, 2);
  });
});
