import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ClaudeProvider } from '../../../src/models/providers/claudeProvider.js';

describe('ClaudeProvider Integration & Configuration', () => {
  test('reports unconfigured state when ANTHROPIC_API_KEY is missing', () => {
    const provider = new ClaudeProvider(undefined);
    assert.equal(provider.providerId, 'claude');
    assert.equal(provider.name, 'claude');
    assert.equal(provider.isConfigured(), false);
  });

  test('reports configured state when explicit API key is provided', () => {
    const provider = new ClaudeProvider('sk-ant-testkey1234567890');
    assert.equal(provider.isConfigured(), true);
  });

  test('throws controlled error on unconfigured generateContent call without leaking keys', async () => {
    const provider = new ClaudeProvider(undefined);
    await assert.rejects(async () => {
      await provider.generateContent({ history: [] });
    }, /unconfigured: ANTHROPIC_API_KEY is not set/i);
  });
});
