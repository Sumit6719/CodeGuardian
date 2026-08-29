import { GoogleGenAI, Type } from '@google/genai';
import {
  IModelProvider,
  ModelGenerateRequest,
  ModelGenerateResponse,
  ModelMessage,
  NormalizedToolCall
} from '../provider.interface.js';
import { NormalizedToolDeclaration } from '../../tools/toolRegistry.js';

export class GeminiProvider implements IModelProvider {
  readonly name = 'gemini';
  readonly providerId = 'gemini';
  private readonly ai: GoogleGenAI;
  private readonly modelName: string;
  private readonly apiKey: string | undefined;

  constructor(apiKey?: string, modelName?: string) {
    this.apiKey = apiKey || process.env.GEMINI_API_KEY;
    this.ai = new GoogleGenAI({ apiKey: this.apiKey || 'UNCONFIGURED' });
    this.modelName = modelName || process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  }

  isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0);
  }

  async generateContent(request: ModelGenerateRequest): Promise<ModelGenerateResponse> {
    const contents = this.translateHistoryToGemini(request.history);
    const tools = request.tools && request.tools.length > 0
      ? [{ functionDeclarations: this.translateToolsToGemini(request.tools) }]
      : undefined;

    const config: Record<string, any> = {};
    if (request.systemInstruction) {
      config.systemInstruction = request.systemInstruction;
    }
    if (tools) {
      config.tools = tools;
    }

    const response = await this.ai.models.generateContent({
      model: this.modelName,
      contents,
      config
    });

    const toolCalls: NormalizedToolCall[] = [];
    if (response.functionCalls && response.functionCalls.length > 0) {
      for (const fc of response.functionCalls) {
        toolCalls.push({
          name: fc.name as string,
          args: (fc.args || {}) as Record<string, any>
        });
      }
    }

    return {
      text: response.text || undefined,
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      raw: response.candidates?.[0]?.content
    };
  }

  private translateHistoryToGemini(history: ModelMessage[]): any[] {
    const geminiContents: any[] = [];

    for (const msg of history) {
      if (msg.raw) {
        // Use preserved candidate content directly (preserves thought signatures)
        geminiContents.push(msg.raw);
        continue;
      }

      const parts: any[] = [];
      for (const part of msg.parts) {
        if ('text' in part) {
          parts.push({ text: part.text });
        } else if ('toolResponse' in part) {
          parts.push({
            functionResponse: {
              name: part.toolResponse.name,
              response: { result: part.toolResponse.response }
            }
          });
        }
      }

      if (parts.length > 0) {
        geminiContents.push({
          role: msg.role === 'model' ? 'model' : 'user',
          parts
        });
      }
    }

    return geminiContents;
  }

  private translateToolsToGemini(declarations: NormalizedToolDeclaration[]): any[] {
    return declarations.map(decl => ({
      name: decl.name,
      description: decl.description,
      parameters: this.translateSchema(decl.parameters)
    }));
  }

  private translateSchema(schema: any): any {
    if (!schema) return schema;

    const mappedProperties: Record<string, any> = {};
    if (schema.properties) {
      for (const [key, prop] of Object.entries<any>(schema.properties)) {
        mappedProperties[key] = {
          type: this.mapType(prop.type),
          description: prop.description
        };
      }
    }

    return {
      type: Type.OBJECT,
      properties: mappedProperties,
      required: schema.required || []
    };
  }

  private mapType(type: string): any {
    switch (type.toLowerCase()) {
      case 'string':
        return Type.STRING;
      case 'number':
        return Type.NUMBER;
      case 'integer':
        return Type.INTEGER;
      case 'boolean':
        return Type.BOOLEAN;
      case 'array':
        return Type.ARRAY;
      case 'object':
        return Type.OBJECT;
      default:
        return Type.STRING;
    }
  }
}
