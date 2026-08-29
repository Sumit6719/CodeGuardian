import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { SecureProcessExecutor } from '../../../src/execution/processExecutor.js';
import { PathGuard } from '../../../src/security/pathGuard.js';
import { CommandProposal, ParsedCommand } from '../../../src/core/types.js';

describe('ProcessLifecycle and Sandboxing Unit Tests', () => {
  let testWorkspace: string;
  let pathGuard: PathGuard;
  let executor: SecureProcessExecutor;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_lifecycle_test_'));
    pathGuard = new PathGuard(testWorkspace);
    executor = new SecureProcessExecutor(pathGuard, {
      timeoutMs: 1500,
      maxStdoutBytes: 500,
      maxStderrBytes: 500
    });
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('scrubs sensitive environment keys aggressively', () => {
    const parentEnv = {
      GEMINI_API_KEY: 'secret-api-key',
      MY_SSH_PASSWORD: 'ssh-pass-phrase',
      AWS_CREDENTIALS: 'aws-tokens',
      SAFE_PATH: '/usr/bin'
    };
    
    // Call private method or inspect behavior via getSanitizedEnv
    const sanitized = (executor as any).getSanitizedEnv(parentEnv);
    assert.equal(sanitized.GEMINI_API_KEY, undefined);
    assert.equal(sanitized.MY_SSH_PASSWORD, undefined);
    assert.equal(sanitized.AWS_CREDENTIALS, undefined);
    // Safe ones should remain if allowed (usually default allows only standard platform keys,
    // but check that sensitive keys are definitely absent)
  });

  it('enforces output truncation boundary and logs truncation indicators', async () => {
    // Generate massive output using a node inline execution
    const largeOutputScript = path.join(testWorkspace, 'large.js');
    fs.writeFileSync(largeOutputScript, 'console.log("A".repeat(1000));');

    const proposal: CommandProposal = {
      command: `node ${largeOutputScript}`,
      workingDirectory: testWorkspace,
      purpose: 'TEST',
      requestedBy: 'AGENT'
    };

    const parsed: ParsedCommand = {
      rawCommand: proposal.command,
      executable: 'node',
      args: [largeOutputScript],
      env: {},
      hasShellOperators: false,
      isDangerous: false
    };

    const result = await executor.execute(proposal, parsed, 'ALLOW');
    assert.ok(result.stdout.length < 1000);
    assert.ok(result.stdout.includes('[STDOUT TRUNCATED AT'));
  });

  it('terminates processes exceeding capability timeouts', async () => {
    const sleepScript = path.join(testWorkspace, 'sleep.js');
    fs.writeFileSync(sleepScript, 'setTimeout(() => {}, 10000);');

    const proposal: CommandProposal = {
      command: `node ${sleepScript}`,
      workingDirectory: testWorkspace,
      purpose: 'TEST',
      requestedBy: 'AGENT'
    };

    const parsed: ParsedCommand = {
      rawCommand: proposal.command,
      executable: 'node',
      args: [sleepScript],
      env: {},
      hasShellOperators: false,
      isDangerous: false
    };

    const startTime = Date.now();
    const result = await executor.execute(proposal, parsed, 'ALLOW');
    const elapsed = Date.now() - startTime;

    assert.ok(elapsed < 5000, `Expected sleep script to be killed quickly, took: ${elapsed}ms`);
    assert.equal(result.timedOut, true);
  });
});
