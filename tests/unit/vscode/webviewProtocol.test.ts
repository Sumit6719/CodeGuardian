import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { validateWebviewMessage, WebviewProtocolError } from '../../../src/vscode/webviewProtocol.js';

describe('WebviewProtocol Runtime Schema Validation & Injection Prevention', () => {
  test('validates valid SUBMIT_PROPOSAL and PING commands', () => {
    const validPing = validateWebviewMessage({ command: 'PING' });
    assert.equal(validPing.command, 'PING');

    const validProp = validateWebviewMessage({ command: 'SUBMIT_PROPOSAL', goal: 'Refactor test' });
    assert.equal(validProp.command, 'SUBMIT_PROPOSAL');
    assert.equal(validProp.goal, 'Refactor test');
  });

  test('rejects unknown or invalid command types', () => {
    assert.throws(() => {
      validateWebviewMessage({ command: 'INVALID_COMMAND' });
    }, WebviewProtocolError);
  });

  test('rejects path traversal and null bytes in path payload', () => {
    assert.throws(() => {
      validateWebviewMessage({ command: 'SUBMIT_PROPOSAL', path: '../../etc/passwd' });
    }, /path traversal or null byte/i);

    assert.throws(() => {
      validateWebviewMessage({ command: 'SUBMIT_PROPOSAL', path: 'src/app.ts\0.js' });
    }, /path traversal or null byte/i);
  });

  test('rejects oversized payloads (> 1MB)', () => {
    const largeStr = 'a'.repeat(1024 * 1024 + 10);
    assert.throws(() => {
      validateWebviewMessage({ command: 'PING', params: { data: largeStr } });
    }, /payload size limit/i);
  });
});
