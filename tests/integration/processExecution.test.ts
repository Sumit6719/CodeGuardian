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

class MockExecutionModelProvider implements IModelProvider {
  readonly name = 'mock-exec-model';
  private step = 0;

  async generateContent(request: ModelGenerateRequest): Promise<ModelGenerateResponse> {
    this.step++;

    // Turn 1: Propose a blocked command (Command Chaining Injection)
    if (this.step === 1) {
      return {
        toolCalls: [
          {
            name: 'execute_command',
            args: {
              command: 'npm test && rm -rf /',
              purpose: 'TEST'
            }
          }
        ]
      };
    }

    // Turn 2: Propose a benign allowed verification command
    if (this.step === 2) {
      // Verify that Turn 1 block payload was returned as feedback
      const lastMsg = request.history[request.history.length - 1];
      const part = lastMsg.parts[0];
      assert.ok('toolResponse' in part);
      assert.ok(JSON.stringify(part.toolResponse).includes('SECURITY_POLICY_BLOCKED'));

      return {
        toolCalls: [
          {
            name: 'execute_command',
            args: {
              command: 'npm test',
              purpose: 'TEST'
            }
          }
        ]
      };
    }

    // Turn 3: Complete
    return {
      text: 'Verification commands finished running.'
    };
  }
}

describe('CodeGuardian v0.3 Process Execution Pipeline Integration', () => {
  let testWorkspace: string;
  let evidenceLogPath: string;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_v3_exec_integration_'));
    evidenceLogPath = path.join(testWorkspace, '.codeguardian', 'evidence.jsonl');

    // Create a mock package.json so "npm test" runs successfully
    fs.writeFileSync(
      path.join(testWorkspace, 'package.json'),
      JSON.stringify({
        name: 'test-pkg',
        scripts: {
          test: 'npx tsc'
        }
      }, null, 2),
      'utf-8'
    );
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('filters dangerous commands and executes allowed verification commands producing chained evidence records', async () => {
    const config = createDefaultConfig(testWorkspace, { maxIterations: 5 });
    const mockModel = new MockExecutionModelProvider();

    let userPromptedCount = 0;
    const testAdapter = new CliAdapter();
    testAdapter.askUserConfirmation = async () => {
      userPromptedCount++;
      return 'ALLOW_ONCE';
    };

    const orchestrator = new AgentOrchestrator(config, mockModel, testAdapter);
    const result = await orchestrator.run('Run verification checks');

    assert.ok(result.summary.includes('Verification commands'));
    assert.equal(userPromptedCount, 0); // Both block and allowlist matches bypass user prompt!

    // Verify evidence ledger logs
    const evidenceLedger = orchestrator.getEvidenceLedger();
    const records = evidenceLedger.readAll();

    // Verify presence of all expected process events
    const eventTypes = records.map(r => r.event);
    assert.ok(eventTypes.includes('PROCESS_PROPOSED'));
    assert.ok(eventTypes.includes('EXECUTABLE_RESOLVED'));
    assert.ok(eventTypes.includes('SCRIPT_ANALYZED'));
    assert.ok(eventTypes.includes('CAPABILITY_CREATED'));
    assert.ok(eventTypes.includes('CAPABILITY_USED'));
    assert.ok(eventTypes.includes('PROCESS_BLOCKED'));
    assert.ok(eventTypes.includes('PROCESS_COMPLETED'));

    // Verify tamper-evident chain integrity
    const chainCheck = evidenceLedger.verifyLedgerIntegrity();
    assert.equal(chainCheck.valid, true);
  });
});
