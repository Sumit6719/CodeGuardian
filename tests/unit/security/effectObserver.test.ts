import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { EffectObserver } from '../../../src/security/effects/effectObserver.js';

describe('EffectObserver Unit Tests', () => {
  let testWorkspace: string;
  let observer: EffectObserver;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_observer_test_'));
    observer = new EffectObserver(testWorkspace);
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('correctly captures empty directory pre-state', () => {
    const preState = observer.captureState();
    assert.equal(preState.files.size, 0);
    assert.ok(preState.directories.has(path.resolve(testWorkspace)));
  });

  it('detects file creation, modification, and deletion', () => {
    // 1. Initial State
    const fileA = path.join(testWorkspace, 'a.txt');
    fs.writeFileSync(fileA, 'initial content');
    const preState = observer.captureState();

    // 2. Modify state
    // Create B
    const fileB = path.join(testWorkspace, 'b.txt');
    fs.writeFileSync(fileB, 'new file');
    
    // Modify A
    fs.writeFileSync(fileA, 'modified content');

    // Delete A and check deletion detection (we will recreate it to test delete separately)
    const postState1 = observer.captureState();
    const effects1 = observer.detectEffects(preState, postState1);

    const fileTypes1 = effects1.filesystem.map(f => f.type);
    assert.ok(fileTypes1.includes('FILE_CREATE'));
    assert.ok(fileTypes1.includes('FILE_WRITE'));

    const createEffect = effects1.filesystem.find(f => f.type === 'FILE_CREATE');
    assert.equal(createEffect?.target, path.resolve(fileB));

    const writeEffect = effects1.filesystem.find(f => f.type === 'FILE_WRITE');
    assert.equal(writeEffect?.target, path.resolve(fileA));

    // 3. Deletion test
    fs.unlinkSync(fileB);
    const postState2 = observer.captureState();
    const effects2 = observer.detectEffects(postState1, postState2);

    const fileTypes2 = effects2.filesystem.map(f => f.type);
    assert.ok(fileTypes2.includes('FILE_DELETE'));
    const deleteEffect = effects2.filesystem.find(f => f.type === 'FILE_DELETE');
    assert.equal(deleteEffect?.target, path.resolve(fileB));
  });

  it('prevents symlink traversal escaping workspace root', () => {
    const tempOutside = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_outside_'));
    const fileOutside = path.join(tempOutside, 'secret.txt');
    fs.writeFileSync(fileOutside, 'secret contents');

    // Create a symlink in workspace pointing outside
    const symlinkPath = path.join(testWorkspace, 'escape_link');
    try {
      fs.symlinkSync(fileOutside, symlinkPath);
    } catch {
      // Symlinks might require admin privileges on Windows; skip if symlink cannot be created
      fs.rmSync(tempOutside, { recursive: true, force: true });
      return;
    }

    const state = observer.captureState();
    // Verify that the file outside the workspace was NOT traversed or captured
    const canonicalOutside = fs.realpathSync(fileOutside);
    assert.equal(state.files.has(canonicalOutside), false);

    // Cleanup
    try {
      fs.unlinkSync(symlinkPath);
      fs.rmSync(tempOutside, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });
});
