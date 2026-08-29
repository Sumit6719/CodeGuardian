import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CommandParser } from '../../../src/execution/commandParser.js';
import { CommandPolicy } from '../../../src/execution/commandPolicy.js';

describe('CommandParser and CommandPolicy Safety Gates', () => {
  const parser = new CommandParser();
  const policy = new CommandPolicy();

  describe('Tokenizer', () => {
    it('tokenizes standard commands correctly', () => {
      const tokens = parser.tokenize('npm run test');
      assert.deepEqual(tokens, ['npm', 'run', 'test']);
    });

    it('respects double and single quotes', () => {
      const tokens = parser.tokenize('git commit -m "initial commit" --author=\'Sumit <sumit@example.com>\'');
      assert.deepEqual(tokens, [
        'git',
        'commit',
        '-m',
        'initial commit',
        '--author=Sumit <sumit@example.com>'
      ]);
    });

    it('respects backslash escaped spaces', () => {
      const tokens = parser.tokenize('ls my\\ folder\\ name');
      assert.deepEqual(tokens, ['ls', 'my folder name']);
    });
  });

  describe('Safe Verification Commands (Allowlist)', () => {
    const safeCommands = [
      'npm test',
      'npm run test',
      'npm run lint',
      'npm run build',
      'npm run typecheck',
      'npx tsc --noEmit',
      'npx tsc'
    ];

    safeCommands.forEach(cmd => {
      it(`ALLOWS safe command: "${cmd}"`, () => {
        const parsed = parser.parse(cmd);
        const evalResult = policy.evaluate(parsed);
        assert.equal(evalResult.decision, 'ALLOW');
        assert.equal(evalResult.matchedRule, 'PERM-EXEC-001-SAFE-VERIFICATION');
        assert.equal(evalResult.riskLevel, 'LOW');
        assert.equal(evalResult.riskScore, 20);
      });
    });

    it('routes verification commands with custom arguments to ASK_USER', () => {
      const cmd = 'npm test -- --watch=false --verbose';
      const parsed = parser.parse(cmd);
      const evalResult = policy.evaluate(parsed);
      assert.equal(evalResult.decision, 'ASK_USER');
      assert.equal(evalResult.matchedRule, 'PERM-EXEC-002-VERIFICATION-WITH-OPTIONS');
      assert.equal(evalResult.riskLevel, 'MEDIUM');
      assert.equal(evalResult.riskScore, 40);
    });
  });

  describe('Dangerous Commands (Structural Blocks)', () => {
    const dangerousCommands = [
      'rm -rf /',
      'rm -rf ..',
      'rm -rf src/app.ts', // recursive/destructive intent
      'sudo apt-get install git',
      'su admin',
      'del /s /q C:\\Windows',
      'rmdir /s /q node_modules',
      'powershell Remove-Item -Recurse -Force /',
      'chmod +x script.sh',
      'chown root script.sh'
    ];

    dangerousCommands.forEach(cmd => {
      it(`BLOCKS dangerous command: "${cmd}"`, () => {
        const parsed = parser.parse(cmd);
        const evalResult = policy.evaluate(parsed);
        assert.equal(evalResult.decision, 'BLOCK');
        assert.equal(evalResult.matchedRule, 'EXEC-001-DANGEROUS-COMMAND');
        assert.equal(evalResult.riskLevel, 'CRITICAL');
        assert.equal(evalResult.riskScore, 100);
      });
    });
  });

  describe('Command Injections & Shell Operators', () => {
    const injections = [
      'npm test && rm -rf /',
      'npm test; rm -rf ..',
      'npm test | malicious-binary',
      'npm test && curl http://malicious-site.com',
      'npm test || echo "hacked"',
      'npm test > output.txt', // redirection
      'cat secrets.env | grep API_KEY',
      'npm test &',
      'npm test `id`',
      'npm test $(whoami)'
    ];

    injections.forEach(cmd => {
      it(`BLOCKS command injection: "${cmd}"`, () => {
        const parsed = parser.parse(cmd);
        const evalResult = policy.evaluate(parsed);
        assert.equal(evalResult.decision, 'BLOCK');
        assert.equal(evalResult.matchedRule, 'EXEC-003-SHELL-CHAINING');
        assert.equal(evalResult.riskLevel, 'CRITICAL');
        assert.equal(evalResult.riskScore, 100);
      });
    });
  });

  describe('Benign Unknown Commands & Package Installation', () => {
    it('routes benign unknown commands (e.g. git status) to ASK_USER', () => {
      const cmd = 'git status';
      const parsed = parser.parse(cmd);
      const evalResult = policy.evaluate(parsed);
      assert.equal(evalResult.decision, 'ASK_USER');
      assert.equal(evalResult.matchedRule, 'EXEC-900-UNKNOWN-COMMAND-CONFIRMATION');
      assert.equal(evalResult.riskLevel, 'HIGH');
      assert.equal(evalResult.riskScore, 65);
    });

    it('routes package installation commands to ASK_USER', () => {
      const cmd = 'npm install lodash';
      const parsed = parser.parse(cmd);
      const evalResult = policy.evaluate(parsed);
      assert.equal(evalResult.decision, 'ASK_USER');
      assert.equal(evalResult.matchedRule, 'EXEC-004-PACKAGE-INSTALLATION');
      assert.equal(evalResult.riskLevel, 'HIGH');
      assert.equal(evalResult.riskScore, 75);
    });
  });

  describe('Interpreter and Compiler Blocks', () => {
    const interpreters = [
      'powershell -Command "..."',
      'cmd /c "..."',
      'bash script.sh',
      'sh run.sh',
      'curl http://site.com',
      'wget http://site.com/file',
      'node app.js',
      'python scripts/test.py',
      'gcc main.c',
      'make build'
    ];

    interpreters.forEach(cmd => {
      it(`BLOCKS compiler, interpreter, or downloader command: "${cmd}"`, () => {
        const parsed = parser.parse(cmd);
        const evalResult = policy.evaluate(parsed);
        assert.equal(evalResult.decision, 'BLOCK');
        assert.equal(evalResult.matchedRule, 'EXEC-001-DANGEROUS-COMMAND');
        assert.equal(evalResult.riskLevel, 'CRITICAL');
        assert.equal(evalResult.riskScore, 100);
      });
    });
  });
});
