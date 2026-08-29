import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { activateCodeGuardianExtension } from '../../../src/vscode/extension.js';

describe('VS Code Extension Activation & Command Registration Unit Tests', () => {
  test('activates extension cleanly with mocked VS Code API', () => {
    const registeredCommands: string[] = [];
    const subscriptions: any[] = [];

    const mockVscode = {
      workspace: {
        workspaceFolders: [{ uri: { fsPath: process.cwd() } }]
      },
      commands: {
        registerCommand: (command: string, callback: Function) => {
          registeredCommands.push(command);
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

    const mockContext = { subscriptions };

    const result = activateCodeGuardianExtension(mockVscode, mockContext);

    assert.equal(result.isInitialized, true);
    assert.equal(registeredCommands.length, 5);
    assert.ok(registeredCommands.includes('codeguardian.start'));
    assert.ok(registeredCommands.includes('codeguardian.audit'));
    assert.ok(registeredCommands.includes('codeguardian.rollback'));
    assert.ok(registeredCommands.includes('codeguardian.openPanel'));
    assert.ok(registeredCommands.includes('codeguardian.showEvidence'));
  });
});
