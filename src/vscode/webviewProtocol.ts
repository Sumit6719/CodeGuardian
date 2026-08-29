export type WebviewCommandType =
  | 'SUBMIT_PROPOSAL'
  | 'APPROVE_ACTION'
  | 'DENY_ACTION'
  | 'TRIGGER_ROLLBACK'
  | 'REQUEST_AUDIT_LOG'
  | 'PING';

export interface WebviewMessagePayload {
  readonly command: WebviewCommandType;
  readonly actionId?: string;
  readonly goal?: string;
  readonly path?: string;
  readonly decision?: 'ALLOW' | 'DENY';
  readonly params?: Record<string, any>;
}

export interface ExtensionResponsePayload {
  readonly type: 'STATE_UPDATE' | 'PERMISSION_REQUEST' | 'AUDIT_DATA' | 'ERROR' | 'PONG';
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
    'SUBMIT_PROPOSAL',
    'APPROVE_ACTION',
    'DENY_ACTION',
    'TRIGGER_ROLLBACK',
    'REQUEST_AUDIT_LOG',
    'PING'
  ];

  if (!raw.command || !validCommands.includes(raw.command)) {
    throw new WebviewProtocolError(`Invalid or unsupported command type: ${String(raw.command)}`);
  }

  // Path validation against path traversal if path parameter is supplied
  if (raw.path && typeof raw.path === 'string') {
    if (raw.path.includes('\0') || raw.path.includes('..')) {
      throw new WebviewProtocolError(`Invalid path payload: path traversal or null byte detected.`);
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
    params: raw.params && typeof raw.params === 'object' ? raw.params : undefined
  };
}
