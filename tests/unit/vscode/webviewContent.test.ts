import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { getWebviewHtml } from '../../../src/vscode/webviewContent.js';

describe('WebviewContent HTML Generator Unit Tests', () => {
  test('generates valid HTML string with CSP nonce and security panels', () => {
    const nonce = 'testnonce123456';
    const html = getWebviewHtml(nonce);

    assert.ok(html.includes(`nonce-${nonce}`));
    assert.ok(html.includes('CodeGuardian Security Panel'));
    assert.ok(html.includes('submitProposal()'));
    assert.ok(html.includes('sendApproval('));
    assert.ok(html.includes('triggerRollback()'));
    assert.ok(html.includes('fetchEvidence()'));
  });
});
