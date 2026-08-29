import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { activateCodeGuardianExtension } from '../../src/vscode/extension.js';

describe('VS Code Extension End-to-End Integration Tests', () => {
  test('activates extension and executes full governed RPC workflow', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-ext-e2e-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-app', scripts: { test: 'node -e "process.exit(0)"' } }));

    const registeredCommands = new Map<string, Function>();

    const mockVscode = {
      workspace: {
        workspaceFolders: [{ uri: { fsPath: tmpDir } }]
      },
      commands: {
        registerCommand: (command: string, callback: Function) => {
          registeredCommands.set(command, callback);
          return { dispose: () => {} };
        },
        executeCommand: (cmd: string) => {}
      },
      window: {
        createWebviewPanel: () => ({
          webview: { html: '', onDidReceiveMessage: () => {}, postMessage: () => {} },
          onDidDispose: () => {}
        })
      },
      ViewColumn: { Two: 2 }
    };

    const mockContext = { subscriptions: [] };

    const extension = activateCodeGuardianExtension(mockVscode, mockContext, tmpDir);
    assert.equal(extension.isInitialized, true);

    // Test RPC handleWebviewMessage calls
    const pingRes = await extension.bridge.handleWebviewMessage({ command: 'PING' });
    assert.equal(pingRes.type, 'PONG');

    const auditRes = await extension.bridge.handleWebviewMessage({ command: 'AUDIT' });
    assert.equal(auditRes.type, 'EVIDENCE_DATA');
    assert.equal(auditRes.success, true);

    const rollbackRes = await extension.bridge.handleWebviewMessage({ command: 'ROLLBACK', actionId: 'latest' });
    assert.equal(rollbackRes.type, 'STATE_UPDATE');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('rejects malicious RPC payloads and injection attempts cleanly', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-ext-inj-'));
    const mockVscode = {
      workspace: { workspaceFolders: [{ uri: { fsPath: tmpDir } }] },
      commands: { registerCommand: () => ({ dispose: () => {} }) }
    };

    const extension = activateCodeGuardianExtension(mockVscode, { subscriptions: [] }, tmpDir);

    const badRes = await extension.bridge.handleWebviewMessage({ command: 'SUBMIT_PROPOSAL', path: '../../etc/passwd' });
    assert.equal(badRes.type, 'ERROR');
    assert.equal(badRes.success, false);
    assert.ok(badRes.error?.includes('path traversal'));

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
