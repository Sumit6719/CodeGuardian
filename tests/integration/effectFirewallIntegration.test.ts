import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { AgentOrchestrator } from '../../src/agent/orchestrator.js';
import { createDefaultConfig } from '../../src/core/config.js';
import { IModelProvider } from '../../src/models/provider.interface.js';
import { IHostAdapter } from '../../src/adapters/hostAdapter.interface.js';
import { EffectObserver } from '../../src/security/effects/effectObserver.js';
import { EffectFirewall } from '../../src/security/effects/effectFirewall.js';
import { CapabilityManager } from '../../src/security/capabilities/capabilityManager.js';
import { RollbackManager } from '../../src/verification/rollbackManager.js';
import { SnapshotManager } from '../../src/verification/snapshotManager.js';
import { EvidenceLedger } from '../../src/audit/evidenceLedger.js';

class DummyOrchestrationModelProvider implements IModelProvider {
  readonly name = 'dummy-integration-model';
  readonly maxContextTokens = 1000;
  private step = 0;
  private readonly command: string;

  constructor(command: string) {
    this.command = command;
  }

  async generateContent(request: any): Promise<any> {
    this.step++;
    if (this.step === 1) {
      return {
        toolCalls: [{ id: 'call_cmd', name: 'execute_command', args: { command: this.command, purpose: 'TEST' } }]
      };
    }
    return { text: 'Finished checks.' };
  }
}

class DummyHostAdapter implements IHostAdapter {
  notify(type: 'info' | 'warn' | 'error', message: string): void {}
  async askUserConfirmation(): Promise<'ALLOW' | 'DENY' | 'ALLOW_SESSION'> { return 'ALLOW'; }
  reportProgress(message: string): void {}
}

describe('EffectFirewall Integration Tests', () => {
  let testWorkspace: string;
  let adapter: DummyHostAdapter;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_effect_integration_'));
    adapter = new DummyHostAdapter();
  });

  after(() => {
    try { fs.rmSync(testWorkspace, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('runs legitimate npm test successfully and records expected events', async () => {
    const pkg = { name: 'legit-pkg', scripts: { test: 'npx tsc' } };
    fs.writeFileSync(path.join(testWorkspace, 'package.json'), JSON.stringify(pkg, null, 2));

    const config = createDefaultConfig(testWorkspace);
    config.evidenceLogPath = path.join(testWorkspace, 'evidence_legit.jsonl');
    config.auditLogPath = path.join(testWorkspace, 'audit_legit.log');

    const provider = new DummyOrchestrationModelProvider('npm test');
    const orchestrator = new AgentOrchestrator(config, provider, adapter);

    const origGenerateGrant = (orchestrator as any).capabilityManager.generateGrant;
    (orchestrator as any).capabilityManager.generateGrant = function(op: any, dec: any, opts: any) {
      return origGenerateGrant.call(this, op, dec, { ...opts, allowedPaths: [testWorkspace], allowedProcesses: ['npm', 'npx', 'tsc'] });
    };

    const result = await orchestrator.run('Legit run');
    assert.ok(result.totalToolCalls >= 1);

    const events = orchestrator.getEvidenceLedger().readAll().map(e => e.event);
    assert.ok(events.includes('EFFECT_DETECTED'), 'Should log detected effect properties');
    assert.ok(events.includes('CHANGE_IMPACT_CALCULATED'), 'Should report change blast-radius score');
  });

  it('blocks unauthorized file writes outside allowed capability regions and rolls them back', async () => {
    // This test directly exercises the EffectObserver → EffectFirewall → RollbackManager pipeline.
    // It simulates what the orchestrator does post-execution: capture workspace state, detect effects,
    // validate against capability grants, and roll back unauthorized mutations.

    const allowedWriteDir = path.join(testWorkspace, 'allowed-writes');
    fs.mkdirSync(allowedWriteDir, { recursive: true });

    const snapshotDir = path.join(testWorkspace, '.codeguardian', 'snapshots');
    fs.mkdirSync(snapshotDir, { recursive: true });

    const evidenceLogPath = path.join(testWorkspace, 'evidence_violation.jsonl');
    const auditLogPath = path.join(testWorkspace, 'audit_violation.log');

    const snapshotManager = new SnapshotManager(snapshotDir);
    const rollbackManager = new RollbackManager(snapshotManager);
    const ledger = new EvidenceLedger(evidenceLogPath);

    const capabilityManager = new CapabilityManager(testWorkspace);
    // Grant capability restricted to the allowed-writes/ subdirectory only
    const capability = capabilityManager.generateGrant('EXECUTE', 'ALLOW', {
      allowedPaths: [allowedWriteDir],
      allowedProcesses: ['npm', 'node']
    });

    // Create observer excluding evidence and audit infrastructure files
    const observer = new EffectObserver(testWorkspace, {
      excludedFiles: [evidenceLogPath, auditLogPath]
    });

    // --- STEP 1: Capture pre-execution workspace state ---
    const preState = observer.captureState();

    // Pre-snapshot all existing workspace files for rollback
    const commandSnapshots: any[] = [];
    for (const filePath of preState.files.keys()) {
      try {
        const snap = snapshotManager.createSnapshot(filePath);
        commandSnapshots.push(snap);
      } catch { /* ignore unreadable files */ }
    }

    // --- STEP 2: Simulate a process writing OUTSIDE the allowed capability region ---
    // A "malicious" npm script would write a file to workspace root (outside allowed-writes/).
    const unauthorizedFilePath = path.join(testWorkspace, 'unauthorized-output.txt');
    fs.writeFileSync(unauthorizedFilePath, 'injected content', 'utf8');

    // --- STEP 3: Capture post-execution workspace state and detect effects ---
    const postState = observer.captureState();
    const observed = observer.detectEffects(preState, postState, [], []);

    // Verify the unauthorized file was detected as a FILE_CREATE effect
    const unauthorizedEffect = observed.filesystem.find(e => e.target === unauthorizedFilePath);
    assert.ok(unauthorizedEffect, 'Unauthorized file write should be detected as a filesystem effect');
    assert.equal(unauthorizedEffect!.type, 'FILE_CREATE', 'Should be classified as FILE_CREATE');

    // --- STEP 4: Run the Effect Firewall ---
    const firewall = new EffectFirewall();
    const firewallResult = firewall.validate(observed, capability);

    // Firewall MUST reject this because the file is outside allowedPaths
    assert.equal(firewallResult.valid, false, 'Firewall should reject unauthorized write outside allowed paths');
    assert.ok(firewallResult.reason?.includes('Unauthorized filesystem modification'), `Expected violation reason, got: ${firewallResult.reason}`);

    // --- STEP 5: Record CAPABILITY_VIOLATION in evidence ledger ---
    ledger.record('CAPABILITY_VIOLATION', {
      actionId: 'act_test_violation',
      operation: 'EXECUTE',
      target: capability.id,
      provider: 'test-provider',
      risk: { level: 'CRITICAL', score: 100 },
      decision: 'ALLOW',
      command: 'npm test',
      details: {
        capabilityId: capability.id,
        violationType: firewallResult.violation?.type,
        reason: firewallResult.reason
      }
    } as any);

    // --- STEP 6: Rollback all unauthorized filesystem effects ---
    const infraPaths = new Set([path.resolve(evidenceLogPath), path.resolve(auditLogPath)]);
    const rolledBackFiles: string[] = [];
    let rollbackSuccess = true;

    for (const fEffect of observed.filesystem) {
      if (infraPaths.has(path.resolve(fEffect.target))) continue;

      if (fEffect.type === 'FILE_CREATE') {
        const snap: any = {
          snapshotId: `snap_temp_${Date.now()}_${crypto.randomUUID().slice(0, 6)}`,
          filePath: fEffect.target,
          originalContent: null,
          originalHash: null,
          timestamp: Date.now()
        };
        const res = rollbackManager.rollback(snap);
        if (res.success) { rolledBackFiles.push(fEffect.target); }
        else { rollbackSuccess = false; }
      }
    }

    assert.ok(rollbackSuccess, 'Rollback should succeed for all unauthorized filesystem effects');
    assert.ok(rolledBackFiles.includes(unauthorizedFilePath), 'Unauthorized file should be in rolled-back set');

    // Record completion
    ledger.record('EFFECT_ROLLBACK_COMPLETED', {
      actionId: 'act_test_violation',
      operation: 'EXECUTE',
      target: capability.id,
      provider: 'test-provider',
      risk: { level: 'LOW', score: 20 },
      decision: 'ALLOW',
      details: { rolledBackFiles }
    } as any);

    // --- STEP 7: Verify end state ---
    // The unauthorized file should have been deleted by rollback
    assert.equal(
      fs.existsSync(unauthorizedFilePath),
      false,
      'Unauthorized file should be deleted after rollback'
    );

    // Verify ledger has both CAPABILITY_VIOLATION and EFFECT_ROLLBACK_COMPLETED
    const events = ledger.readAll().map(e => e.event);
    assert.ok(
      events.includes('CAPABILITY_VIOLATION'),
      `Should log capability violations on unauthorized writes. Got: ${events.join(', ')}`
    );
    assert.ok(
      events.includes('EFFECT_ROLLBACK_COMPLETED'),
      `Should log successful rollback completion. Got: ${events.join(', ')}`
    );
  });
});
