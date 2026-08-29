import {
  IModelProvider,
  ModelGenerateRequest,
  ModelGenerateResponse,
  NormalizedToolCall
} from '../provider.interface.js';

export class ClaudeProvider implements IModelProvider {
  readonly name = 'claude';
  readonly providerId = 'claude';
  private readonly apiKey: string | undefined;
  private readonly modelName: string;

  constructor(apiKey?: string, modelName?: string) {
    this.apiKey = apiKey || process.env.ANTHROPIC_API_KEY;
    this.modelName = modelName || process.env.CLAUDE_MODEL || 'claude-3-5-sonnet-20241022';
  }

  isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0);
  }

  async generateContent(request: ModelGenerateRequest): Promise<ModelGenerateResponse> {
    if (!this.isConfigured()) {
      throw new Error('ClaudeProvider is unconfigured: ANTHROPIC_API_KEY is not set.');
    }

    try {
      // Direct REST fetch call to Anthropic Messages API without unhandled crashes
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': this.apiKey!,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: this.modelName,
          max_tokens: 4096,
          system: request.systemInstruction,
          messages: this.translateHistoryToClaude(request.history),
          tools: request.tools ? this.translateToolsToClaude(request.tools) : undefined
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Anthropic API error (${response.status}): ${this.sanitizeError(errorText)}`);
      }

      const data: any = await response.json();
      const toolCalls: NormalizedToolCall[] = [];
      let textContent = '';

      if (data.content && Array.isArray(data.content)) {
        for (const block of data.content) {
          if (block.type === 'text') {
            textContent += block.text;
          } else if (block.type === 'tool_use') {
            toolCalls.push({
              id: block.id,
              name: block.name,
              args: block.input || {}
            });
          }
        }
      }

      return {
        text: textContent || undefined,
        toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
        raw: data
      };
    } catch (err: any) {
      throw new Error(`ClaudeProvider execution error: ${this.sanitizeError(err.message)}`);
    }
  }

  private translateHistoryToClaude(history: any[]): any[] {
    return history.map(msg => {
      const role = msg.role === 'model' ? 'assistant' : 'user';
      let content = '';
      for (const part of msg.parts) {
        if ('text' in part) {
          content += part.text;
        } else if ('toolResponse' in part) {
          content += JSON.stringify(part.toolResponse);
        }
      }
      return { role, content };
    });
  }

  private translateToolsToClaude(tools: any[]): any[] {
    return tools.map(t => ({
      name: t.name,
      description: t.description,
      input_schema: t.parameters || { type: 'object', properties: {} }
    }));
  }

  private sanitizeError(str: string): string {
    if (!str) return '';
    return str.replace(/sk-ant-[a-zA-Z0-9_\-\.]{20,}/g, '[REDACTED_CLAUDE_KEY]');
  }
}
