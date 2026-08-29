import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RiskEngine } from '../../../src/security/riskEngine.js';

describe('RiskEngine Deterministic Evaluation', () => {
  const engine = new RiskEngine();

  it('evaluates reading normal source code as LOW or MEDIUM risk', () => {
    const result = engine.evaluate({
      operation: 'READ',
      sensitivity: 'MEDIUM',
      blastRadius: 'LOCAL',
      isWorkspaceContained: true,
      targetPath: 'src/index.js'
    });

    assert.ok(result.level === 'LOW' || result.level === 'MEDIUM');
    assert.ok(result.score < 60);
  });

  it('evaluates listing workspace directory as LOW risk', () => {
    const result = engine.evaluate({
      operation: 'LIST',
      sensitivity: 'LOW',
      blastRadius: 'LOCAL',
      isWorkspaceContained: true,
      targetPath: 'src'
    });

    assert.equal(result.level, 'LOW');
    assert.ok(result.score < 30);
  });

  it('evaluates writing leaf source file as MEDIUM or HIGH risk', () => {
    const result = engine.evaluate({
      operation: 'WRITE',
      sensitivity: 'MEDIUM',
      blastRadius: 'LOCAL',
      isWorkspaceContained: true,
      targetPath: 'src/auth.js'
    });

    assert.ok(result.level === 'MEDIUM' || result.level === 'HIGH');
    assert.ok(result.score >= 30);
  });

  it('evaluates modifying package.json as HIGH risk', () => {
    const result = engine.evaluate({
      operation: 'WRITE',
      sensitivity: 'HIGH',
      blastRadius: 'WORKSPACE',
      isWorkspaceContained: true,
      targetPath: 'package.json'
    });

    assert.equal(result.level, 'HIGH');
    assert.ok(result.score >= 60);
  });

  it('evaluates file deletion as HIGH risk', () => {
    const result = engine.evaluate({
      operation: 'DELETE',
      sensitivity: 'MEDIUM',
      blastRadius: 'LOCAL',
      isWorkspaceContained: true,
      targetPath: 'src/old.js'
    });

    assert.equal(result.level, 'HIGH');
  });

  it('evaluates writing to CRITICAL .env as CRITICAL risk', () => {
    const result = engine.evaluate({
      operation: 'WRITE',
      sensitivity: 'CRITICAL',
      blastRadius: 'LOCAL',
      isWorkspaceContained: true,
      targetPath: '.env'
    });

    assert.equal(result.level, 'CRITICAL');
    assert.ok(result.score >= 85);
  });

  it('evaluates any operation outside workspace as CRITICAL risk', () => {
    const result = engine.evaluate({
      operation: 'READ',
      sensitivity: 'LOW',
      blastRadius: 'SYSTEM',
      isWorkspaceContained: false,
      targetPath: '../../etc/passwd'
    });

    assert.equal(result.level, 'CRITICAL');
    assert.equal(result.score, 100);
  });
});
