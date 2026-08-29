import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { NpmScriptAnalyzer } from '../../../src/execution/npmScriptAnalyzer.js';
import { CommandParser } from '../../../src/execution/commandParser.js';
import { CommandPolicy } from '../../../src/execution/commandPolicy.js';

describe('NpmScriptAnalyzer Unit Tests', () => {
  let testWorkspace: string;
  let analyzer: NpmScriptAnalyzer;
  const parser = new CommandParser();
  const policy = new CommandPolicy();

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_script_test_'));
    analyzer = new NpmScriptAnalyzer(testWorkspace, parser, policy, {
      maxDepth: 3,
      maxScripts: 5
    });
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('allows safe npm script chains', () => {
    const pkg = {
      scripts: {
        test: 'npm run verify',
        verify: 'npx tsc --noEmit'
      }
    };
    fs.writeFileSync(path.join(testWorkspace, 'package.json'), JSON.stringify(pkg));

    const result = analyzer.analyze('test');
    assert.equal(result.success, true);
    assert.deepEqual(result.chain, ['test', 'verify']);
  });

  it('blocks malicious scripts containing shell operators', () => {
    const pkg = {
      scripts: {
        test: 'npm run verify',
        verify: 'npx tsc && malicious_command'
      }
    };
    fs.writeFileSync(path.join(testWorkspace, 'package.json'), JSON.stringify(pkg));

    const result = analyzer.analyze('test');
    assert.equal(result.success, false);
    assert.equal(result.matchedRule, 'EXEC-003-SHELL-CHAINING');
  });

  it('blocks cycles recursively', () => {
    const pkg = {
      scripts: {
        a: 'npm run b',
        b: 'npm run a'
      }
    };
    fs.writeFileSync(path.join(testWorkspace, 'package.json'), JSON.stringify(pkg));

    const result = analyzer.analyze('a');
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('cycle detected'));
  });

  it('blocks depth violations exceeding limit', () => {
    const pkg = {
      scripts: {
        a: 'npm run b',
        b: 'npm run c',
        c: 'npm run d',
        d: 'npm run e'
      }
    };
    fs.writeFileSync(path.join(testWorkspace, 'package.json'), JSON.stringify(pkg));

    const result = analyzer.analyze('a');
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('recursion depth'));
  });
});
