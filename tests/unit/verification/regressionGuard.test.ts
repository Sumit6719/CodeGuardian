import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { RegressionGuard } from '../../../src/verification/regressionGuard.js';
import { IsolationFactory } from '../../../src/security/isolation/isolationFactory.js';
import { CapabilityManager } from '../../../src/security/capabilities/capabilityManager.js';
import { RollbackManager } from '../../../src/verification/rollbackManager.js';
import { SnapshotManager } from '../../../src/verification/snapshotManager.js';
import { EvidenceLedger } from '../../../src/audit/evidenceLedger.js';

describe('RegressionGuard Isolated Test Runner & Automatic Rollback', () => {
  test('detects npm test runner deterministically from package.json metadata', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-reg-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ scripts: { test: 'node -e "process.exit(0)"' } }));

    const isoFactory = new IsolationFactory();
    const capManager = new CapabilityManager(tmpDir);
    const snapManager = new SnapshotManager(path.join(tmpDir, 'snapshots'));
    const rollbackManager = new RollbackManager(snapManager);
    const ledger = new EvidenceLedger(path.join(tmpDir, 'evidence.jsonl'));

    const guard = new RegressionGuard(tmpDir, isoFactory, capManager, rollbackManager, ledger);
    const runner = guard.detectTestRunner();

    assert.equal(runner?.executable, 'npm');
    assert.deepEqual(runner?.args, ['test']);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('prevents recursive execution loop when anti-recursion flag is set', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-reg-'));
    const isoFactory = new IsolationFactory();
    const capManager = new CapabilityManager(tmpDir);
    const snapManager = new SnapshotManager(path.join(tmpDir, 'snapshots'));
    const rollbackManager = new RollbackManager(snapManager);
    const ledger = new EvidenceLedger(path.join(tmpDir, 'evidence.jsonl'));

    const guard = new RegressionGuard(tmpDir, isoFactory, capManager, rollbackManager, ledger);

    process.env.CODEGUARDIAN_REGRESSION_ACTIVE = 'true';
    const result = await guard.runRegressionCheck();
    process.env.CODEGUARDIAN_REGRESSION_ACTIVE = 'false';

    assert.equal(result.success, true);
    assert.equal(result.runner, 'recursion-guard');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
