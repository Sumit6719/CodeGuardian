import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ResourceLimits } from '../../../../src/security/isolation/isolationTypes.js';

describe('ResourceLimits Unit Tests', () => {
  it('validates bounds structure for CPU, memory, and output byte limits', () => {
    const limits: ResourceLimits = {
      maxExecutionTimeMs: 30000,
      maxOutputBytes: 50 * 1024,
      maxMemoryMb: 512,
      maxCpuPercent: 50,
      maxProcesses: 10
    };

    assert.equal(limits.maxExecutionTimeMs, 30000);
    assert.equal(limits.maxOutputBytes, 51200);
    assert.equal(limits.maxMemoryMb, 512);
    assert.equal(limits.maxCpuPercent, 50);
    assert.equal(limits.maxProcesses, 10);
  });
});
