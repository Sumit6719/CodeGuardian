import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { ModelProviderRegistry } from '../../src/models/modelRegistry.js';
import { GeminiProvider } from '../../src/models/providers/geminiProvider.js';
import { ClaudeProvider } from '../../src/models/providers/claudeProvider.js';
import { OpenAIProvider } from '../../src/models/providers/openAIProvider.js';
import { OllamaProvider } from '../../src/models/providers/ollamaProvider.js';
import { ModelDisagreementDetector } from '../../src/models/disagreement.js';
import { AgentOrchestrator } from '../../src/agent/orchestrator.js';
import { createDefaultConfig } from '../../src/core/config.js';
import { HostAdapter, HostConfirmationRequest, HostConfirmationResponse } from '../../src/adapters/hostAdapter.interface.js';

class MockHostAdapter implements HostAdapter {
  async askUserConfirmation(): Promise<HostConfirmationResponse> {
    return 'ALLOW';
  }
  notify(): void {}
  showDiff(): void {}
}

describe('Multi-Model Provider Orchestration & Consensus Integration', () => {
  test('registers multiple providers and analyzes consensus/disagreement', () => {
    const gemini = new GeminiProvider('gemini_key');
    const claude = new ClaudeProvider('claude_key');
    const openai = new OpenAIProvider('openai_key');
    const ollama = new OllamaProvider('http://localhost:11434');

    const registry = new ModelProviderRegistry([gemini, claude, openai, ollama]);
    assert.equal(registry.getAllProviders().length, 4);

    const detector = new ModelDisagreementDetector();
    const analysis = detector.analyze([
      { providerId: 'gemini', proposal: { operation: 'WRITE', targetPath: 'src/app.ts', content: 'v1' }, riskScore: 20 },
      { providerId: 'claude', proposal: { operation: 'WRITE', targetPath: 'src/app.ts', content: 'v1' }, riskScore: 20 }
    ]);

    assert.equal(analysis.consensus, true);
    assert.equal(analysis.disagreementScore, 0.0);
  });

  test('orchestrator initializes cleanly with multi-model registry and disagreement detector', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-mm-'));
    const config = createDefaultConfig(tmpDir);
    const provider = new GeminiProvider('mock_key');
    const registry = new ModelProviderRegistry([provider]);
    const adapter = new MockHostAdapter();

    const orchestrator = new AgentOrchestrator(config, provider, adapter, { modelRegistry: registry });
    assert.ok(orchestrator.getEvidenceLedger());

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
