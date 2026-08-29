import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { AgentOrchestrator } from '../../src/agent/orchestrator.js';
import { IModelProvider, ModelGenerateRequest, ModelGenerateResponse } from '../../src/models/provider.interface.js';
import { CliAdapter } from '../../src/adapters/cli/cliAdapter.js';
import { createDefaultConfig } from '../../src/core/config.js';
import { AuditLogger } from '../../src/audit/auditLogger.js';

/**
 * Mock model provider that emits controlled action proposals
 */
class MockModelProvider implements IModelProvider {
  readonly name = 'mock-test-model';
  private step = 0;

  async generateContent(_request: ModelGenerateRequest): Promise<ModelGenerateResponse> {
    this.step++;

    // Step 1: Safe list_files (Should be ALLOWED)
    if (this.step === 1) {
      return {
        toolCalls: [
          {
            name: 'list_files',
            args: { directory: 'src' }
          }
        ]
      };
    }

    // Step 2: Path traversal attack (Should be BLOCKED by PathGuard/Policy)
    if (this.step === 2) {
      return {
        toolCalls: [
          {
            name: 'read_file',
            args: { file_path: '../../outside_secret.txt' }
          }
        ]
      };
    }

    // Step 3: Critical asset write attack on .env (Should be BLOCKED by Policy)
    if (this.step === 3) {
      return {
        toolCalls: [
          {
            name: 'write_file',
            args: { file_path: '.env', content: 'EXPOSED_SECRET=true' }
          }
        ]
      };
    }

    // Step 4: Normal file write that user will DENY
    if (this.step === 4) {
      return {
        toolCalls: [
          {
            name: 'write_file',
            args: { file_path: 'src/denied.js', content: 'console.log("denied");' }
          }
        ]
      };
    }

    // Step 5: Normal file write that user will ALLOW
    if (this.step === 5) {
      return {
        toolCalls: [
          {
            name: 'write_file',
            args: { file_path: 'src/allowed.js', content: 'console.log("allowed");' }
          }
        ]
      };
    }

    // Step 6: Final report
    return {
      text: 'Audit and review complete. Safe fixes applied.'
    };
  }
}

describe('CodeGuardian Governed Pipeline End-to-End Integration', () => {
  let testWorkspace: string;
  let auditLogPath: string;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_integration_'));
    fs.mkdirSync(path.join(testWorkspace, 'src'), { recursive: true });
    fs.writeFileSync(path.join(testWorkspace, 'src', 'index.js'), 'const a = 1;');
    fs.writeFileSync(path.join(testWorkspace, '.env'), 'SECRET=original');
    auditLogPath = path.join(testWorkspace, '.codeguardian', 'audit.jsonl');
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('correctly executes full governance lifecycle across turns', async () => {
    const config = createDefaultConfig(testWorkspace, { maxIterations: 10 });
    const mockModel = new MockModelProvider();

    // Adapter configured to DENY on step 4, and ALLOW_ONCE on step 5
    let promptCallCount = 0;
    const testAdapter = new CliAdapter();
    testAdapter.askUserConfirmation = async () => {
      promptCallCount++;
      if (promptCallCount === 1) {
        return 'DENY'; // Deny the first prompt (step 4)
      }
      return 'ALLOW_ONCE'; // Allow the second prompt (step 5)
    };

    const orchestrator = new AgentOrchestrator(config, mockModel, testAdapter);

    const result = await orchestrator.run('Perform security review');

    assert.ok(result.summary.includes('Audit and review complete'));
    assert.equal(result.totalModifications, 1); // Only step 5 wrote to disk

    // Verify written file
    const allowedFile = path.join(testWorkspace, 'src', 'allowed.js');
    assert.equal(fs.existsSync(allowedFile), true);
    assert.equal(fs.readFileSync(allowedFile, 'utf-8'), 'console.log("allowed");');

    // Verify denied file was NOT created
    const deniedFile = path.join(testWorkspace, 'src', 'denied.js');
    assert.equal(fs.existsSync(deniedFile), false);

    // Verify .env was NOT overwritten
    assert.equal(fs.readFileSync(path.join(testWorkspace, '.env'), 'utf-8'), 'SECRET=original');

    // Verify Audit Log records
    const auditLogger = new AuditLogger(auditLogPath);
    const records = auditLogger.readAll();

    assert.equal(records.length, 5);

    // Record 1: list_files -> SUCCESS
    assert.equal(records[0].operation, 'LIST');
    assert.equal(records[0].policyDecision, 'ALLOW');
    assert.equal(records[0].executionResult, 'SUCCESS');

    // Record 2: traversal -> BLOCKED
    assert.equal(records[1].policyDecision, 'BLOCK');
    assert.equal(records[1].executionResult, 'BLOCKED');

    // Record 3: .env write -> BLOCKED
    assert.equal(records[2].policyDecision, 'BLOCK');
    assert.equal(records[2].executionResult, 'BLOCKED');

    // Record 4: denied write -> DENIED
    assert.equal(records[3].policyDecision, 'ASK_USER');
    assert.equal(records[3].userDecision, 'DENY');
    assert.equal(records[3].executionResult, 'DENIED');

    // Record 5: allowed write -> SUCCESS with snapshot & hashes
    assert.equal(records[4].policyDecision, 'ASK_USER');
    assert.equal(records[4].userDecision, 'ALLOW_ONCE');
    assert.equal(records[4].executionResult, 'SUCCESS');
    assert.ok(records[4].afterHash);
  });
});
