import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ModelDisagreementDetector } from '../../../src/models/disagreement.js';

describe('ModelDisagreementDetector Multi-Model Consensus & Divergence', () => {
  test('returns 0.0 disagreement score for single provider proposal', () => {
    const detector = new ModelDisagreementDetector();
    const result = detector.analyze([
      {
        providerId: 'gemini',
        proposal: { operation: 'WRITE', targetPath: 'src/index.ts', content: 'console.log("hi");' },
        riskScore: 20
      }
    ]);

    assert.equal(result.disagreementScore, 0.0);
    assert.equal(result.consensus, true);
    assert.equal(result.riskEscalation, false);
  });

  test('detects operation mismatch and target path mismatch across providers', () => {
    const detector = new ModelDisagreementDetector();
    const result = detector.analyze([
      {
        providerId: 'gemini',
        proposal: { operation: 'WRITE', targetPath: 'src/index.ts', content: 'a' },
        riskScore: 10
      },
      {
        providerId: 'claude',
        proposal: { operation: 'DELETE', targetPath: 'src/other.ts' },
        riskScore: 70
      }
    ]);

    assert.ok(result.disagreementScore >= 0.75);
    assert.equal(result.consensus, false);
    assert.equal(result.riskEscalation, true);
    assert.ok(result.reasons.some(r => r.includes('Operation mismatch')));
  });

  test('escalates risk level when proposals involve sensitive .env assets', () => {
    const detector = new ModelDisagreementDetector();
    const result = detector.analyze([
      {
        providerId: 'gemini',
        proposal: { operation: 'WRITE', targetPath: '.env', content: 'SECRET=1' }
      },
      {
        providerId: 'openai',
        proposal: { operation: 'WRITE', targetPath: '.env', content: 'SECRET=2' }
      }
    ]);

    assert.equal(result.riskEscalation, true);
    assert.ok(result.reasons.some(r => r.includes('.env')));
  });
});
