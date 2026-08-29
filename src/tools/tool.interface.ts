import { OperationType, ToolResult, CapabilityGrant } from '../core/types.js';
import { SnapshotManager } from '../verification/snapshotManager.js';
import { IntegrityVerifier } from '../verification/integrityVerifier.js';

import { RollbackManager } from '../verification/rollbackManager.js';
import { SyntaxVerifier } from '../verification/syntaxVerifier.js';
import { CommandParser } from '../execution/commandParser.js';
import { CommandPolicy } from '../execution/commandPolicy.js';
import { SecureProcessExecutor } from '../execution/processExecutor.js';

export interface ToolExecutionContext {
  workspaceRoot: string;
  snapshotManager: SnapshotManager;
  integrityVerifier: IntegrityVerifier;
  rollbackManager?: RollbackManager;
  syntaxVerifier?: SyntaxVerifier;
  commandParser?: CommandParser;
  commandPolicy?: CommandPolicy;
  processExecutor?: SecureProcessExecutor;
  capability?: CapabilityGrant;
}

export interface ToolParameterSchema {
  type: string;
  description: string;
  enum?: string[];
}

export interface ToolSchema {
  type: 'object';
  properties: Record<string, ToolParameterSchema>;
  required: string[];
}

export interface ITool {
  readonly name: string;
  readonly description: string;
  readonly operation: OperationType;
  readonly parameters: ToolSchema;
  execute(args: Record<string, any>, context: ToolExecutionContext): Promise<ToolResult>;
}
