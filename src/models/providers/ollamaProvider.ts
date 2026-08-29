import {
  IModelProvider,
  ModelGenerateRequest,
  ModelGenerateResponse,
  NormalizedToolCall
} from '../provider.interface.js';

export class OllamaProvider implements IModelProvider {
  readonly name = 'ollama';
  readonly providerId = 'ollama';
  private readonly host: string;
  private readonly modelName: string;
  private isAvailableHost = false;

  constructor(host?: string, modelName?: string) {
    this.host = (host || process.env.OLLAMA_HOST || 'http://localhost:11434').replace(/\/$/, '');
    this.modelName = modelName || process.env.OLLAMA_MODEL || 'qwen2.5-coder';
  }

  isConfigured(): boolean {
    // Ollama is local, so configured requires a non-empty host URL
    return Boolean(this.host && this.host.trim().length > 0);
  }

  /**
   * Health check for local Ollama server instance
   */
  async checkHealth(): Promise<boolean> {
    try {
      const res = await fetch(`${this.host}/api/tags`, { method: 'GET' });
      this.isAvailableHost = res.ok;
      return res.ok;
    } catch {
      this.isAvailableHost = false;
      return false;
    }
  }

  async generateContent(request: ModelGenerateRequest): Promise<ModelGenerateResponse> {
    if (!this.isConfigured()) {
      throw new Error('OllamaProvider is unconfigured: OLLAMA_HOST is not set.');
    }

    try {
      const messages: any[] = [];
      if (request.systemInstruction) {
        messages.push({ role: 'system', content: request.systemInstruction });
      }

      for (const msg of request.history) {
        const role = msg.role === 'model' ? 'assistant' : 'user';
        let text = '';
        for (const p of msg.parts) {
          if ('text' in p) text += p.text;
          else if ('toolResponse' in p) text += JSON.stringify(p.toolResponse);
        }
        messages.push({ role, content: text });
      }

      const response = await fetch(`${this.host}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.modelName,
          messages,
          stream: false
        })
      });

      if (!response.ok) {
        throw new Error(`Ollama API error (${response.status}): ${await response.text()}`);
      }

      const data: any = await response.json();
      const content = data.message?.content || '';

      // Parse JSON tool calls if model outputs structured JSON tool calls in text
      const toolCalls: NormalizedToolCall[] = [];
      try {
        if (content.trim().startsWith('{') && content.includes('"name"') && content.includes('"args"')) {
          const parsed = JSON.parse(content.trim());
          if (parsed.name && parsed.args) {
            toolCalls.push({ name: parsed.name, args: parsed.args });
          }
        }
      } catch {
        // ignore plain text output
      }

      return {
        text: content,
        toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
        raw: data
      };
    } catch (err: any) {
      throw new Error(`OllamaProvider execution error: ${err.message}`);
    }
  }
}
