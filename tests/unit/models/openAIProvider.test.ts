import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { OpenAIProvider } from '../../../src/models/providers/openAIProvider.js';

describe('OpenAIProvider Integration & Configuration', () => {
  test('reports unconfigured state when OPENAI_API_KEY is missing', () => {
    const provider = new OpenAIProvider(undefined);
    assert.equal(provider.providerId, 'openai');
    assert.equal(provider.name, 'openai');
    assert.equal(provider.isConfigured(), false);
  });

  test('reports configured state when explicit API key is provided', () => {
    const provider = new OpenAIProvider('sk-testkey12345678901234567890');
    assert.equal(provider.isConfigured(), true);
  });

  test('throws controlled error on unconfigured generateContent call without leaking keys', async () => {
    const provider = new OpenAIProvider(undefined);
    await assert.rejects(async () => {
      await provider.generateContent({ history: [] });
    }, /unconfigured: OPENAI_API_KEY is not set/i);
  });
});
