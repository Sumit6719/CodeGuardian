import { ITool } from './tool.interface.js';
import { ListFilesTool } from './filesystem/listFilesTool.js';
import { ReadFileTool } from './filesystem/readFileTool.js';
import { WriteFileTool } from './filesystem/writeFileTool.js';
import { ExecuteCommandTool } from './execution/executeCommandTool.js';
import { OperationType } from '../core/types.js';

export interface NormalizedToolDeclaration {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, any>;
    required: string[];
  };
}

export class ToolRegistry {
  private readonly tools = new Map<string, ITool>();

  constructor() {
    // Register default v0.1 & v0.3 tools
    this.register(new ListFilesTool());
    this.register(new ReadFileTool());
    this.register(new WriteFileTool());
    this.register(new ExecuteCommandTool());
  }

  register(tool: ITool): void {
    this.tools.set(tool.name, tool);
  }

  get(name: string): ITool | undefined {
    return this.tools.get(name);
  }

  getAll(): ITool[] {
    return Array.from(this.tools.values());
  }

  getDeclarations(): NormalizedToolDeclaration[] {
    return this.getAll().map(tool => ({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters
    }));
  }

  /**
   * Infers operation type from tool name or metadata
   */
  inferOperation(toolName: string): OperationType {
    const tool = this.tools.get(toolName);
    return tool ? tool.operation : 'UNKNOWN';
  }

  /**
   * Extracts the intended target path from tool arguments
   */
  extractTargetPath(toolName: string, args: Record<string, any>): string | undefined {
    if (args.file_path) return String(args.file_path);
    if (args.directory) return String(args.directory);
    if (args.path) return String(args.path);
    if (args.target) return String(args.target);
    if (args.working_directory) return String(args.working_directory);
    return undefined;
  }
}
