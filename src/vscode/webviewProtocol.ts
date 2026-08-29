export type WebviewCommandType =
  | 'PING'
  | 'START'
  | 'AUDIT'
  | 'SUBMIT_PROPOSAL'
  | 'APPROVE'
  | 'REJECT'
  | 'ROLLBACK'
  | 'GET_STATE'
  | 'GET_DIFF'
  | 'GET_EVIDENCE'
  | 'SELECT_MODEL'
  // Legacy aliases
  | 'APPROVE_ACTION'
  | 'DENY_ACTION'
  | 'TRIGGER_ROLLBACK'
  | 'REQUEST_AUDIT_LOG';

export interface WebviewMessagePayload {
  readonly command: WebviewCommandType;
  readonly actionId?: string;
  readonly goal?: string;
  readonly path?: string;
  readonly decision?: 'ALLOW' | 'DENY';
  readonly modelId?: string;
  readonly params?: Record<string, any>;
}

export interface ExtensionResponsePayload {
  readonly type: 'STATE_UPDATE' | 'PERMISSION_REQUEST' | 'AUDIT_DATA' | 'DIFF_DATA' | 'EVIDENCE_DATA' | 'ERROR' | 'PONG';
  readonly actionId?: string;
  readonly success: boolean;
  readonly payload?: any;
  readonly error?: string;
}

export class WebviewProtocolError extends Error {
  constructor(message: string) {
    super(`WebviewProtocolError: ${message}`);
    this.name = 'WebviewProtocolError';
  }
}

/**
 * Validates incoming RPC messages from Webview UI to prevent payload injection attacks.
 */
export function validateWebviewMessage(raw: any): WebviewMessagePayload {
  if (!raw || typeof raw !== 'object') {
    throw new WebviewProtocolError('Message payload must be a non-null JSON object.');
  }

  const validCommands: WebviewCommandType[] = [
    'PING',
    'START',
    'AUDIT',
    'SUBMIT_PROPOSAL',
    'APPROVE',
    'REJECT',
    'ROLLBACK',
    'GET_STATE',
    'GET_DIFF',
    'GET_EVIDENCE',
    'SELECT_MODEL',
    'APPROVE_ACTION',
    'DENY_ACTION',
    'TRIGGER_ROLLBACK',
    'REQUEST_AUDIT_LOG'
  ];

  if (!raw.command || !validCommands.includes(raw.command)) {
    throw new WebviewProtocolError(`Invalid or unsupported command type: ${String(raw.command)}`);
  }

  // Path validation against path traversal if path parameter is supplied
  if (raw.path && typeof raw.path === 'string') {
    if (raw.path.includes('\0') || raw.path.includes('..')) {
      throw new WebviewProtocolError('Invalid path payload: path traversal or null byte detected.');
    }
  }

  // Model ID validation if supplied
  if (raw.modelId && typeof raw.modelId === 'string') {
    const validModels = ['gemini', 'claude', 'openai', 'ollama'];
    if (!validModels.includes(raw.modelId.toLowerCase())) {
      throw new WebviewProtocolError(`Invalid model provider requested: ${raw.modelId}`);
    }
  }

  // Oversized payload check (1MB cap)
  const jsonStr = JSON.stringify(raw);
  if (jsonStr.length > 1024 * 1024) {
    throw new WebviewProtocolError('Webview message exceeds maximum allowed payload size limit of 1MB.');
  }

  return {
    command: raw.command,
    actionId: raw.actionId ? String(raw.actionId) : undefined,
    goal: raw.goal ? String(raw.goal) : undefined,
    path: raw.path ? String(raw.path) : undefined,
    decision: raw.decision === 'ALLOW' || raw.decision === 'DENY' ? raw.decision : undefined,
    modelId: raw.modelId ? String(raw.modelId) : undefined,
    params: raw.params && typeof raw.params === 'object' ? raw.params : undefined
  };
}
