import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { PathGuard } from '../../../src/security/pathGuard.js';
import { PathTraversalError } from '../../../src/core/errors.js';

describe('PathGuard Security Containment', () => {
  let testWorkspace: string;
  let guard: PathGuard;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_test_pg_'));
    fs.mkdirSync(path.join(testWorkspace, 'src', 'utils'), { recursive: true });
    fs.writeFileSync(path.join(testWorkspace, 'src', 'index.js'), 'console.log("hello");');
    guard = new PathGuard(testWorkspace);
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore cleanup error
    }
  });

  it('allows access to valid relative files inside the workspace', () => {
    const res = guard.validate('src/index.js');
    assert.equal(res.allowed, true);
    assert.equal(res.relativePath, 'src/index.js');
  });

  it('allows access to subdirectories inside the workspace', () => {
    const res = guard.validate('src/utils');
    assert.equal(res.allowed, true);
    assert.equal(res.relativePath, 'src/utils');
  });

  it('allows access using canonical absolute paths within workspace', () => {
    const abs = path.join(testWorkspace, 'src', 'index.js');
    const res = guard.validate(abs);
    assert.equal(res.allowed, true);
    assert.equal(res.relativePath, 'src/index.js');
  });

  it('blocks simple ../ path traversal escaping workspace', () => {
    const res = guard.validate('../outside.txt');
    assert.equal(res.allowed, false);
    assert.match(res.error || '', /escapes workspace/i);
  });

  it('blocks multi-level ../../../ path traversal', () => {
    const res = guard.validate('../../etc/passwd');
    assert.equal(res.allowed, false);
    assert.match(res.error || '', /escapes workspace/i);
  });

  it('blocks absolute paths outside workspace', () => {
    const outside = process.platform === 'win32' ? 'C:\\Windows\\System32\\calc.exe' : '/etc/shadow';
    const res = guard.validate(outside);
    assert.equal(res.allowed, false);
    assert.match(res.error || '', /escapes workspace/i);
  });

  it('blocks Windows-style backslash traversal', () => {
    const res = guard.validate('..\\..\\secret.txt');
    assert.equal(res.allowed, false);
  });

  it('blocks null byte injections', () => {
    const res = guard.validate('src/index.js\0.png');
    assert.equal(res.allowed, false);
    assert.match(res.error || '', /null byte/i);
  });

  it('assertAllowed throws PathTraversalError for invalid paths', () => {
    assert.throws(
      () => guard.assertAllowed('../escape.txt'),
      (err: any) => err instanceof PathTraversalError
    );
  });
});
