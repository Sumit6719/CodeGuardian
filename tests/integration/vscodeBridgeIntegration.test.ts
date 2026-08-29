import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { ExtensionHostBridge } from '../../src/vscode/extensionBridge.js';
import { WebviewPanelController } from '../../src/vscode/webviewPanelController.js';
import { AgentOrchestrator } from '../../src/agent/orchestrator.js';
import { createDefaultConfig } from '../../src/core/config.js';
import { GeminiProvider } from '../../src/models/providers/geminiProvider.js';
import { HostAdapter, HostConfirmationResponse } from '../../src/adapters/hostAdapter.interface.js';

class MockHostAdapter implements HostAdapter {
  async askUserConfirmation(): Promise<HostConfirmationResponse> {
    return 'ALLOW';
  }
  notify(): void {}
  showDiff(): void {}
}

describe('VS Code Extension Bridge & Governed Execution Integration', () => {
  test('routes validated PING and AUDIT_LOG messages through ExtensionHostBridge', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-vsc-'));
    const config = createDefaultConfig(tmpDir);
    const provider = new GeminiProvider('mock_key');
    const adapter = new MockHostAdapter();
    const orchestrator = new AgentOrchestrator(config, provider, adapter);

    const bridge = new ExtensionHostBridge(orchestrator);

    const pingRes = await bridge.handleWebviewMessage({ command: 'PING' });
    assert.equal(pingRes.type, 'PONG');
    assert.equal(pingRes.success, true);

    const auditRes = await bridge.handleWebviewMessage({ command: 'REQUEST_AUDIT_LOG' });
    assert.equal(auditRes.type, 'AUDIT_DATA');
    assert.equal(auditRes.success, true);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('rejects malformed commands and injection attacks safely', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-vsc2-'));
    const config = createDefaultConfig(tmpDir);
    const provider = new GeminiProvider('mock_key');
    const adapter = new MockHostAdapter();
    const orchestrator = new AgentOrchestrator(config, provider, adapter);

    const bridge = new ExtensionHostBridge(orchestrator);

    const badRes = await bridge.handleWebviewMessage({ command: 'SUBMIT_PROPOSAL', path: '../../etc/passwd' });
    assert.equal(badRes.type, 'ERROR');
    assert.equal(badRes.success, false);
    assert.ok(badRes.error?.includes('path traversal'));

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('WebviewPanelController redacts secrets before sending UI updates', () => {
    const controller = new WebviewPanelController();
    let receivedPayload: any = null;
    controller.setMessageListener(msg => {
      receivedPayload = msg;
    });

    controller.postMessage({
      type: 'STATE_UPDATE',
      success: true,
      payload: { apiKey: 'sk-ant-testkey12345678901234567890' }
    });

    assert.ok(receivedPayload);
    assert.equal(JSON.stringify(receivedPayload).includes('sk-ant-testkey'), false);
    assert.equal(JSON.stringify(receivedPayload).includes('[REDACTED_SECRET]'), true);
  });
});
