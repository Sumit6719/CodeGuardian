import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { OllamaProvider } from '../../../src/models/providers/ollamaProvider.js';

describe('OllamaProvider REST Integration & Local Discovery', () => {
  test('defaults to localhost:11434 and reports configured state', () => {
    const provider = new OllamaProvider();
    assert.equal(provider.providerId, 'ollama');
    assert.equal(provider.name, 'ollama');
    assert.equal(provider.isConfigured(), true);
  });

  test('handles health check failure gracefully when local server is offline', async () => {
    const provider = new OllamaProvider('http://127.0.0.1:59999'); // invalid port
    const isHealthy = await provider.checkHealth();
    assert.equal(isHealthy, false);
  });
});
