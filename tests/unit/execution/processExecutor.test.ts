import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { PathGuard } from '../../../src/security/pathGuard.js';
import { SecureProcessExecutor } from '../../../src/execution/processExecutor.js';
import { CommandProposal } from '../../../src/core/types.js';
import { CommandParser } from '../../../src/execution/commandParser.js';

describe('SecureProcessExecutor Sandbox & Limits Enforcement', () => {
  let testWorkspace: string;
  let pathGuard: PathGuard;
  let executor: SecureProcessExecutor;
  const parser = new CommandParser();

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_executor_test_'));
    pathGuard = new PathGuard(testWorkspace);
    executor = new SecureProcessExecutor(pathGuard, {
      timeoutMs: 1500, // short timeout for test runs
      maxStdoutBytes: 500, // small limit to trigger truncation
      maxStderrBytes: 500,
      allowedEnvKeys: ['PATH', 'APPDATA', 'SAFE_OS_VAR']
    });
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('enforces working directory workspace boundary (blocks outside directories)', async () => {
    const proposal: CommandProposal = {
      command: 'npm test',
      workingDirectory: path.resolve(testWorkspace, '..'), // outside workspace
      purpose: 'TEST',
      requestedBy: 'AGENT'
    };
    const parsed = parser.parse(proposal.command);

    await assert.rejects(
      async () => {
        await executor.execute(proposal, parsed, 'ALLOW');
      },
      (err: any) => {
        return err.name === 'PathTraversalError' && err.message.includes('resolves outside workspace root');
      }
    );
  });

  it('sanitizes child process environment variables (scrubs credentials/tokens)', () => {
    // Inject mock credentials in parent process.env
    process.env.GEMINI_API_KEY = 'super_secret_token_12345';
    process.env.MY_SECRET_DB_PASSWORD = 'password';
    process.env.SAFE_OS_VAR = 'normal_system_setting';

    const customEnv = {
      CUSTOM_API_KEY: 'custom_secret',
      BENIGN_ENV: 'all_good'
    };

    const sanitized = executor.getSanitizedEnv(customEnv);

    // Whitelisted OS settings remain if safe
    assert.equal(sanitized.SAFE_OS_VAR, 'normal_system_setting');
    assert.equal(sanitized.BENIGN_ENV, 'all_good');

    // Sensitive credentials are fully scrubbed
    assert.equal(sanitized.GEMINI_API_KEY, undefined);
    assert.equal(sanitized.MY_SECRET_DB_PASSWORD, undefined);
    assert.equal(sanitized.CUSTOM_API_KEY, undefined);

    // Clean up parent env
    delete process.env.GEMINI_API_KEY;
    delete process.env.MY_SECRET_DB_PASSWORD;
    delete process.env.SAFE_OS_VAR;
  });

  it('terminates process tree on execution timeout', async () => {
    // We execute a node script that sleeps for 10 seconds.
    // Timeout is configured to 1.5 seconds.
    const sleepCommand = 'node -e "setTimeout(() => { console.log(\'done\'); }, 10000);"';
    
    // We need to bypass parser blocker for node execution in tests by creating custom parser result
    const parsed = {
      rawCommand: sleepCommand,
      executable: 'node',
      args: ['-e', 'setTimeout(() => { console.log(\'done\'); }, 10000);'],
      env: {},
      hasShellOperators: false,
      isDangerous: false
    };

    const proposal: CommandProposal = {
      command: sleepCommand,
      workingDirectory: testWorkspace,
      purpose: 'TEST',
      requestedBy: 'AGENT'
    };

    const result = await executor.execute(proposal, parsed, 'ALLOW');

    assert.equal(result.timedOut, true);
    // On Windows, child processes killed by taskkill exit with non-zero (often 1) instead of null
    assert.ok(result.exitCode === null || result.exitCode !== 0);
    assert.ok(result.durationMs >= 1400); // executed for at least 1.4s
    assert.ok(!result.stdout.includes('done')); // Process was killed before completion
  });

  it('truncates excessive process output safely (prevents buffer bloat)', async () => {
    // Generate output that exceeds 500 bytes limit
    const printCommand = 'node -e "console.log(\'X\'.repeat(1000));"';

    const parsed = {
      rawCommand: printCommand,
      executable: 'node',
      args: ['-e', 'console.log(\'X\'.repeat(1000));'],
      env: {},
      hasShellOperators: false,
      isDangerous: false
    };

    const proposal: CommandProposal = {
      command: printCommand,
      workingDirectory: testWorkspace,
      purpose: 'TEST',
      requestedBy: 'AGENT'
    };

    const result = await executor.execute(proposal, parsed, 'ALLOW');

    assert.ok(result.stdout.length > 0);
    assert.ok(result.stdout.length <= 600); // 500 bytes + small truncation message
    assert.ok(result.stdout.includes('TRUNCATED'));
  });
});
