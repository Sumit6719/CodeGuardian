import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { SnapshotManager } from '../../../src/verification/snapshotManager.js';
import { RollbackManager } from '../../../src/verification/rollbackManager.js';

describe('RollbackManager Verified State Restoration', () => {
  let testWorkspace: string;
  let snapshotDir: string;
  let snapshotManager: SnapshotManager;
  let rollbackManager: RollbackManager;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_rollback_test_'));
    snapshotDir = path.join(testWorkspace, '.codeguardian', 'snapshots');
    snapshotManager = new SnapshotManager(snapshotDir);
    rollbackManager = new RollbackManager(snapshotManager);
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('rolls back and verifies modified existing files', () => {
    const filePath = path.join(testWorkspace, 'existing.js');
    const originalContent = 'export const API_VERSION = "1.0";\n';
    fs.writeFileSync(filePath, originalContent, 'utf-8');

    // 1. Snapshot taken
    const snapshot = snapshotManager.createSnapshot(filePath);

    // 2. File modified
    fs.writeFileSync(filePath, 'export const API_VERSION = "corrupted";\n', 'utf-8');

    // 3. Rollback executed
    const result = rollbackManager.rollback(snapshot);

    assert.equal(result.success, true);
    assert.equal(result.verified, true);
    assert.equal(result.restoredHash, snapshot.originalHash);
    assert.equal(fs.readFileSync(filePath, 'utf-8'), originalContent);
  });

  it('rolls back and verifies newly created files (deletes file)', () => {
    const filePath = path.join(testWorkspace, 'newly_created.js');

    // 1. Snapshot of non-existent file
    const snapshot = snapshotManager.createSnapshot(filePath);
    assert.equal(snapshot.originalContent, null);

    // 2. AI creates file
    fs.writeFileSync(filePath, 'console.log("unwanted file");', 'utf-8');
    assert.equal(fs.existsSync(filePath), true);

    // 3. Rollback executed
    const result = rollbackManager.rollback(snapshot);

    assert.equal(result.success, true);
    assert.equal(result.verified, true);
    assert.equal(fs.existsSync(filePath), false);
  });

  it('fails verification if restored file hash does not match original hash', () => {
    const filePath = path.join(testWorkspace, 'tampered.js');
    const originalContent = 'console.log("clean");\n';
    fs.writeFileSync(filePath, originalContent, 'utf-8');

    const snapshot = snapshotManager.createSnapshot(filePath);

    // AI modifies file
    fs.writeFileSync(filePath, 'console.log("dirty");\n', 'utf-8');

    // Simulate corrupted snapshot backup on disk
    const corruptedSnapshot = {
      ...snapshot,
      originalContent: 'console.log("tampered");\n' // content doesn't match originalHash
    };

    const result = rollbackManager.rollback(corruptedSnapshot);

    assert.equal(result.success, false);
    assert.equal(result.verified, false);
    assert.match(result.error || '', /hash.*does not match/i);
  });

  it('returns failure if snapshot cannot be found', () => {
    const result = rollbackManager.rollback('non_existent_snapshot_id');
    assert.equal(result.success, false);
    assert.equal(result.verified, false);
    assert.match(result.error || '', /snapshot not found/i);
  });
});
