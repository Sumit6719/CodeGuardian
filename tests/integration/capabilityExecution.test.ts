import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { AgentOrchestrator } from '../../src/agent/orchestrator.js';
import { createDefaultConfig } from '../../src/core/config.js';
import { IModelProvider, ModelMessage } from '../../src/models/provider.interface.js';
import { IHostAdapter } from '../../src/adapters/hostAdapter.interface.js';

class DummyProvider implements IModelProvider {
  readonly name = 'dummy-model';
  readonly maxContextTokens = 1000;
  
  private step = 0;

  async generateContent(request: any): Promise<any> {
    this.step++;
    if (this.step === 1) {
      return {
        toolCalls: [
          {
            id: 'call_1',
            name: 'execute_command',
            args: {
              command: 'npm test',
              purpose: 'TEST'
            }
          }
        ]
      };
    }
    return {
      text: 'Goal accomplished. Tests have executed successfully.'
    };
  }
}

class DummyHostAdapter implements IHostAdapter {
  notify(type: 'info' | 'warn' | 'error', message: string): void {}
  async askUserConfirmation(): Promise<'ALLOW' | 'DENY' | 'ALLOW_SESSION'> {
    return 'ALLOW';
  }
  reportProgress(message: string): void {}
}

describe('CapabilityExecution Integration Tests', () => {
  let testWorkspace: string;
  let orchestrator: AgentOrchestrator;
  let config: any;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_integration_test_'));
    
    // Create package.json scripts configuration
    const pkg = {
      name: 'integration-pkg',
      scripts: {
        test: 'npx tsc'
      }
    };
    fs.writeFileSync(path.join(testWorkspace, 'package.json'), JSON.stringify(pkg, null, 2));

    config = createDefaultConfig(testWorkspace);
    config.evidenceLogPath = path.join(testWorkspace, 'evidence.jsonl');
    config.auditLogPath = path.join(testWorkspace, 'audit.log');

    const provider = new DummyProvider();
    const adapter = new DummyHostAdapter();
    orchestrator = new AgentOrchestrator(config, provider, adapter);
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('runs proposed npm test command and validates recursive script capability pipeline', async () => {
    const result = await orchestrator.run('Execute verification script tests');

    assert.ok(result.totalToolCalls >= 1);
    
    // Retrieve evidence ledger and verify the logs
    const ledger = orchestrator.getEvidenceLedger();
    const events = ledger.readAll();

    const eventTypes = events.map(e => e.event);
    
    // Verify that the capability events are registered
    assert.ok(eventTypes.includes('EXECUTABLE_RESOLVED'), 'Should resolve requested command executable safely');
    assert.ok(eventTypes.includes('SCRIPT_ANALYZED'), 'Should recursively check scripts inside package.json');
    assert.ok(eventTypes.includes('CAPABILITY_CREATED'), 'Should issue CapabilityGrant to control execution boundaries');
    assert.ok(eventTypes.includes('CAPABILITY_USED'), 'Should track capability utilization during child processes');
    assert.ok(eventTypes.includes('PROCESS_COMPLETED'), 'Should complete execution with status updates');

    // Verify evidence log hash integrity matches
    const integrity = ledger.verifyLedgerIntegrity();
    assert.equal(integrity.valid, true, 'Ledger hash integrity verification failed');
  });
});
