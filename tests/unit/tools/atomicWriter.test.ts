import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { WriteFileTool } from '../../../src/tools/filesystem/writeFileTool.js';
import { SnapshotManager } from '../../../src/verification/snapshotManager.js';
import { IntegrityVerifier } from '../../../src/verification/integrityVerifier.js';

describe('Atomic Write and Snapshot Preservation', () => {
  let testWorkspace: string;
  let snapshotDir: string;
  let snapshotManager: SnapshotManager;
  let integrityVerifier: IntegrityVerifier;
  let writer: WriteFileTool;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_test_writer_'));
    snapshotDir = path.join(testWorkspace, '.codeguardian', 'snapshots');
    snapshotManager = new SnapshotManager(snapshotDir);
    integrityVerifier = new IntegrityVerifier();
    writer = new WriteFileTool();
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('successfully creates and writes a new file atomically', async () => {
    const targetFile = path.join(testWorkspace, 'src', 'newFile.js');
    const content = 'export const test = 42;\n';

    const result = await writer.execute(
      { file_path: targetFile, content },
      { workspaceRoot: testWorkspace, snapshotManager, integrityVerifier }
    );

    assert.equal(result.success, true);
    assert.equal(fs.existsSync(targetFile), true);
    assert.equal(fs.readFileSync(targetFile, 'utf-8'), content);
    assert.equal(result.data.beforeHash, null);
    assert.ok(result.data.afterHash);
  });

  it('modifies an existing file atomically while preserving original snapshot', async () => {
    const targetFile = path.join(testWorkspace, 'src', 'existing.js');
    const originalContent = 'const original = true;\n';
    fs.writeFileSync(targetFile, originalContent, 'utf-8');

    const newContent = 'const updated = true;\n';
    const result = await writer.execute(
      { file_path: targetFile, content: newContent },
      { workspaceRoot: testWorkspace, snapshotManager, integrityVerifier }
    );

    assert.equal(result.success, true);
    assert.equal(fs.readFileSync(targetFile, 'utf-8'), newContent);

    // Verify snapshot was created with original content
    const snapshot = snapshotManager.getSnapshot(result.data.snapshotId);
    assert.ok(snapshot);
    assert.equal(snapshot.originalContent, originalContent);
  });

  it('allows restoring the original state from a snapshot', async () => {
    const targetFile = path.join(testWorkspace, 'src', 'rollbackMe.js');
    const originalContent = 'const safe = "original";';
    fs.writeFileSync(targetFile, originalContent, 'utf-8');

    const result = await writer.execute(
      { file_path: targetFile, content: 'const broken = "modified";' },
      { workspaceRoot: testWorkspace, snapshotManager, integrityVerifier }
    );

    assert.equal(result.success, true);
    assert.equal(fs.readFileSync(targetFile, 'utf-8'), 'const broken = "modified";');

    // Perform manual rollback
    const restored = snapshotManager.restore(result.data.snapshotId);
    assert.equal(restored, true);
    assert.equal(fs.readFileSync(targetFile, 'utf-8'), originalContent);
  });

  it('rejects invalid non-string content safely without touching file', async () => {
    const targetFile = path.join(testWorkspace, 'src', 'untouched.js');
    const originalContent = 'const untouched = true;';
    fs.writeFileSync(targetFile, originalContent, 'utf-8');

    const result = await writer.execute(
      { file_path: targetFile, content: 12345 as any },
      { workspaceRoot: testWorkspace, snapshotManager, integrityVerifier }
    );

    assert.equal(result.success, false);
    assert.equal(fs.readFileSync(targetFile, 'utf-8'), originalContent);
  });
});
