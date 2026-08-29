import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { WebviewPanelController } from '../../../src/vscode/webviewPanelController.js';

describe('WebviewPanelController Secret Redaction & State Unit Tests', () => {
  test('generates valid random nonces for CSP', () => {
    const controller = new WebviewPanelController();
    const nonce1 = controller.generateNonce();
    const nonce2 = controller.generateNonce();

    assert.equal(nonce1.length, 32);
    assert.notEqual(nonce1, nonce2);
  });

  test('scrubs sensitive credentials from state payloads', () => {
    const controller = new WebviewPanelController();
    let sentMessage: any = null;

    controller.setMessageListener(msg => {
      sentMessage = msg;
    });

    controller.postMessage({
      type: 'STATE_UPDATE',
      success: true,
      payload: {
        token: 'sk-ant-12345678901234567890',
        apiKey: 'sk-openai12345678901234567890'
      }
    });

    assert.ok(sentMessage);
    const str = JSON.stringify(sentMessage);
    assert.equal(str.includes('sk-ant-'), false);
    assert.equal(str.includes('sk-openai'), false);
    assert.equal(str.includes('[REDACTED_SECRET]'), true);
  });
});
