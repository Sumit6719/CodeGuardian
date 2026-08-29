import { NormalizedToolDeclaration } from '../tools/toolRegistry.js';

export type ModelRole = 'user' | 'model' | 'system' | 'tool';

export interface NormalizedToolCall {
  id?: string;
  name: string;
  args: Record<string, any>;
}

export interface NormalizedToolResponse {
  name: string;
  response: Record<string, any>;
}

export interface ModelMessage {
  role: ModelRole;
  parts: Array<
    | { text: string }
    | { toolCall: NormalizedToolCall }
    | { toolResponse: NormalizedToolResponse }
  >;
  raw?: any; // To store provider-specific candidate content if needed (e.g. Gemini thought signatures)
}

export interface ModelGenerateRequest {
  systemInstruction?: string;
  history: ModelMessage[];
  tools?: NormalizedToolDeclaration[];
}

export interface ModelGenerateResponse {
  text?: string;
  toolCalls?: NormalizedToolCall[];
  raw?: any;
}

export interface IModelProvider {
  readonly name: string;
  generateContent(request: ModelGenerateRequest): Promise<ModelGenerateResponse>;
}
