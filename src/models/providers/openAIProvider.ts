import {
  IModelProvider,
  ModelGenerateRequest,
  ModelGenerateResponse,
  NormalizedToolCall
} from '../provider.interface.js';

export class OpenAIProvider implements IModelProvider {
  readonly name = 'openai';
  readonly providerId = 'openai';
  private readonly apiKey: string | undefined;
  private readonly modelName: string;

  constructor(apiKey?: string, modelName?: string) {
    this.apiKey = apiKey || process.env.OPENAI_API_KEY;
    this.modelName = modelName || process.env.OPENAI_MODEL || 'gpt-4o';
  }

  isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0);
  }

  async generateContent(request: ModelGenerateRequest): Promise<ModelGenerateResponse> {
    if (!this.isConfigured()) {
      throw new Error('OpenAIProvider is unconfigured: OPENAI_API_KEY is not set.');
    }

    try {
      const messages: any[] = [];
      if (request.systemInstruction) {
        messages.push({ role: 'system', content: request.systemInstruction });
      }
      messages.push(...this.translateHistoryToOpenAI(request.history));

      const tools = request.tools ? this.translateToolsToOpenAI(request.tools) : undefined;

      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: this.modelName,
          messages,
          tools,
          temperature: 0.2
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenAI API error (${response.status}): ${this.sanitizeError(errorText)}`);
      }

      const data: any = await response.json();
      const choice = data.choices?.[0]?.message;

      const toolCalls: NormalizedToolCall[] = [];
      if (choice?.tool_calls && Array.isArray(choice.tool_calls)) {
        for (const tc of choice.tool_calls) {
          let parsedArgs = {};
          try {
            parsedArgs = JSON.parse(tc.function.arguments || '{}');
          } catch {
            parsedArgs = {};
          }
          toolCalls.push({
            id: tc.id,
            name: tc.function.name,
            args: parsedArgs
          });
        }
      }

      return {
        text: choice?.content || undefined,
        toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
        raw: data
      };
    } catch (err: any) {
      throw new Error(`OpenAIProvider execution error: ${this.sanitizeError(err.message)}`);
    }
  }

  private translateHistoryToOpenAI(history: any[]): any[] {
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

  private translateToolsToOpenAI(tools: any[]): any[] {
    return tools.map(t => ({
      type: 'function',
      function: {
        name: t.name,
        description: t.description,
        parameters: t.parameters || { type: 'object', properties: {} }
      }
    }));
  }

  private sanitizeError(str: string): string {
    if (!str) return '';
    return str.replace(/sk-[a-zA-Z0-9_\-\.]{20,}/g, '[REDACTED_OPENAI_KEY]');
  }
}
