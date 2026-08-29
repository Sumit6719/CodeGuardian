import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { ExecutableResolver } from '../../../src/execution/executableResolver.js';
import { PathGuard } from '../../../src/security/pathGuard.js';

describe('ExecutableResolver Unit Tests', () => {
  let testWorkspace: string;
  let pathGuard: PathGuard;
  let resolver: ExecutableResolver;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_resolver_test_'));
    pathGuard = new PathGuard(testWorkspace);
    resolver = new ExecutableResolver(pathGuard);
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('correctly resolves absolute system paths as SYSTEM and trusted', () => {
    // Resolve node using process.execPath (always outside workspace)
    const result = resolver.resolve(process.execPath);
    assert.equal(result.source, 'SYSTEM');
    assert.equal(result.trusted, true);
  });

  it('correctly resolves relative paths inside workspace as WORKSPACE and untrusted', () => {
    const localBinDir = path.join(testWorkspace, 'node_modules', '.bin');
    fs.mkdirSync(localBinDir, { recursive: true });
    
    const localFakeNpm = path.join(localBinDir, process.platform === 'win32' ? 'npm.cmd' : 'npm');
    fs.writeFileSync(localFakeNpm, '#!/bin/sh\necho fake npm');

    const result = resolver.resolve(path.relative(testWorkspace, localFakeNpm));
    assert.equal(result.source, 'WORKSPACE');
    assert.equal(result.trusted, false);
  });

  it('resolves common CLI name to system path and flags it as trusted if found', () => {
    const result = resolver.resolve('node');
    assert.equal(result.source, 'SYSTEM');
    assert.equal(result.trusted, true);
  });

  it('returns UNKNOWN source and untrusted if binary does not exist', () => {
    const result = resolver.resolve('non-existent-binary-xyz');
    assert.equal(result.source, 'UNKNOWN');
    assert.equal(result.trusted, false);
  });
});
