import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ModelProviderRegistry } from '../../../src/models/modelRegistry.js';
import { GeminiProvider } from '../../../src/models/providers/geminiProvider.js';
import { ClaudeProvider } from '../../../src/models/providers/claudeProvider.js';
import { OpenAIProvider } from '../../../src/models/providers/openAIProvider.js';
import { OllamaProvider } from '../../../src/models/providers/ollamaProvider.js';

describe('ModelProviderRegistry Multi-Model Discovery & Selection', () => {
  test('registers providers and enforces duplicate providerId rejection', () => {
    const registry = new ModelProviderRegistry();
    const p1 = new GeminiProvider('dummy_key');
    registry.registerProvider(p1);

    assert.equal(registry.getAllProviders().length, 1);
    assert.equal(registry.getProvider('gemini')?.providerId, 'gemini');

    assert.throws(() => {
      registry.registerProvider(new GeminiProvider('key2'));
    }, /already registered/i);
  });

  test('filters configured providers based on isConfigured() status', () => {
    const gemini = new GeminiProvider('gemini_secret_key');
    const claude = new ClaudeProvider(undefined); // unconfigured (no key)
    const openai = new OpenAIProvider(undefined); // unconfigured (no key)
    const ollama = new OllamaProvider('http://localhost:11434'); // configured host

    const registry = new ModelProviderRegistry([gemini, claude, openai, ollama]);

    assert.equal(registry.getAllProviders().length, 4);
    const configured = registry.getConfiguredProviders();
    assert.equal(configured.length, 2); // gemini and ollama
    assert.equal(configured.some(p => p.providerId === 'gemini'), true);
    assert.equal(configured.some(p => p.providerId === 'ollama'), true);
  });

  test('selects preferred provider if configured, or falls back to first configured provider', () => {
    const gemini = new GeminiProvider('gemini_secret_key');
    const claude = new ClaudeProvider('claude_secret_key');

    const registry = new ModelProviderRegistry([gemini, claude]);

    const selectedClaude = registry.selectProvider('claude');
    assert.equal(selectedClaude.providerId, 'claude');

    const selectedDefault = registry.selectProvider();
    assert.equal(selectedDefault.providerId, 'gemini');
  });

  test('throws descriptive error if no configured provider exists', () => {
    const claude = new ClaudeProvider(undefined);
    const registry = new ModelProviderRegistry([claude]);

    assert.throws(() => {
      registry.selectProvider('claude');
    }, /No configured model providers available/i);
  });
});
