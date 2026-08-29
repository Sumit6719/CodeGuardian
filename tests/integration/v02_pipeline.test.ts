import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { AgentOrchestrator } from '../../src/agent/orchestrator.js';
import { IModelProvider, ModelGenerateRequest, ModelGenerateResponse } from '../../src/models/provider.interface.js';
import { CliAdapter } from '../../src/adapters/cli/cliAdapter.js';
import { createDefaultConfig } from '../../src/core/config.js';
import { EvidenceLedger } from '../../src/audit/evidenceLedger.js';
import { WriteFileTool } from '../../src/tools/filesystem/writeFileTool.js';
import { SnapshotManager } from '../../src/verification/snapshotManager.js';
import { IntegrityVerifier } from '../../src/verification/integrityVerifier.js';
import { RollbackManager } from '../../src/verification/rollbackManager.js';
import { SyntaxVerifier } from '../../src/verification/syntaxVerifier.js';

class MockV2ModelProvider implements IModelProvider {
  readonly name = 'mock-v2-model';
  private step = 0;

  async generateContent(request: ModelGenerateRequest): Promise<ModelGenerateResponse> {
    this.step++;

    // Turn 1: Propose invalid JavaScript code (Syntax Error)
    if (this.step === 1) {
      return {
        toolCalls: [
          {
            name: 'write_file',
            args: {
              file_path: 'src/syntaxError.js',
              content: 'function broken(a, b { return a + b;'
            }
          }
        ]
      };
    }

    // Turn 2: Agent received syntax error feedback, now proposes valid corrected code
    if (this.step === 2) {
      // Verify that the error message was fed back to the model in history
      const lastMsg = request.history[request.history.length - 1];
      const part = lastMsg.parts[0];
      assert.ok('toolResponse' in part);
      assert.ok(JSON.stringify(part.toolResponse).includes('SYNTAX_VERIFICATION_FAILED'));

      return {
        toolCalls: [
          {
            name: 'write_file',
            args: {
              file_path: 'src/syntaxError.js',
              content: 'function fixed(a, b) {\n  return a + b;\n}\nexport default fixed;\n'
            }
          }
        ]
      };
    }

    // Turn 3: Complete
    return {
      text: 'Code successfully corrected with verified syntax.'
    };
  }
}

describe('CodeGuardian v0.2 Evidence & Verification Pipeline Integration', () => {
  let testWorkspace: string;
  let evidenceLogPath: string;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_v2_integration_'));
    fs.mkdirSync(path.join(testWorkspace, 'src'), { recursive: true });
    evidenceLogPath = path.join(testWorkspace, '.codeguardian', 'evidence.jsonl');
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('rejects syntax errors pre-apply and applies valid fixes with verified evidence chain', async () => {
    const config = createDefaultConfig(testWorkspace, { maxIterations: 5 });
    const mockModel = new MockV2ModelProvider();

    let userPromptedCount = 0;
    const testAdapter = new CliAdapter();
    testAdapter.askUserConfirmation = async () => {
      userPromptedCount++;
      return 'ALLOW_ONCE';
    };

    const orchestrator = new AgentOrchestrator(config, mockModel, testAdapter);
    const result = await orchestrator.run('Fix broken code');

    assert.ok(result.summary.includes('Code successfully corrected'));
    assert.equal(result.totalModifications, 1);

    // Notice: User was only prompted ONCE (for the valid turn 2), NOT for the syntax error in turn 1!
    assert.equal(userPromptedCount, 1);

    // Verify written file
    const targetFile = path.join(testWorkspace, 'src', 'syntaxError.js');
    assert.equal(fs.existsSync(targetFile), true);
    assert.ok(fs.readFileSync(targetFile, 'utf-8').includes('function fixed'));

    // Verify evidence ledger
    const evidenceLedger = orchestrator.getEvidenceLedger();
    const records = evidenceLedger.readAll();

    assert.equal(records.length, 2);

    // Record 1: SYNTAX_VERIFICATION_FAILED
    assert.equal(records[0].event, 'SYNTAX_VERIFICATION_FAILED');
    assert.equal(records[0].data.syntax, 'FAIL');
    assert.equal(records[0].data.execution, 'FAILURE');

    // Record 2: ACTION_VERIFIED
    assert.equal(records[1].event, 'ACTION_VERIFIED');
    assert.equal(records[1].data.syntax, 'PASS');
    assert.equal(records[1].data.execution, 'SUCCESS');
    assert.equal(records[1].data.verification, 'PASS');
    assert.ok(records[1].data.proposedSha256);
    assert.ok(records[1].data.diffSummary);

    // Verify tamper-evident cryptographic hash chain integrity
    const chainCheck = evidenceLedger.verifyLedgerIntegrity();
    assert.equal(chainCheck.valid, true);
    assert.equal(chainCheck.totalRecords, 2);
  });

  it('executes atomic rollback and restores verified state when post-write integrity fails', async () => {
    const targetPath = path.join(testWorkspace, 'src', 'corruptPost.js');
    const originalContent = 'export const safe = "initial_v1";\n';
    fs.writeFileSync(targetPath, originalContent, 'utf-8');

    const snapshotDir = path.join(testWorkspace, '.codeguardian', 'snapshots');
    const snapshotManager = new SnapshotManager(snapshotDir);
    const integrityVerifier = new IntegrityVerifier();
    const rollbackManager = new RollbackManager(snapshotManager);
    const syntaxVerifier = new SyntaxVerifier();
    const writer = new WriteFileTool();

    // Create custom verifier that simulates a post-write integrity check failure
    const failingIntegrityVerifier = new IntegrityVerifier();
    failingIntegrityVerifier.verify = () => ({
      valid: false,
      errors: ['Simulated unexpected post-write disk corruption.']
    });

    const res = await writer.execute(
      { file_path: targetPath, content: 'export const unsafe = "corrupted_v2";\n' },
      {
        workspaceRoot: testWorkspace,
        snapshotManager,
        integrityVerifier: failingIntegrityVerifier,
        rollbackManager,
        syntaxVerifier
      }
    );

    assert.equal(res.success, false);
    assert.match(res.error || '', /Integrity\/syntax check failed.*automatically rolled back/i);

    // Verify the file was restored to its exact original content
    assert.equal(fs.readFileSync(targetPath, 'utf-8'), originalContent);
  });
});
