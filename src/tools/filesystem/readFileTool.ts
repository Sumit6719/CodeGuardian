import fs from 'fs';
import path from 'path';
import { ITool, ToolExecutionContext, ToolSchema } from '../tool.interface.js';
import { OperationType, ToolResult } from '../../core/types.js';

export class ReadFileTool implements ITool {
  readonly name = 'read_file';
  readonly description = 'Read the text content of a file within the workspace.';
  readonly operation: OperationType = 'READ';

  readonly parameters: ToolSchema = {
    type: 'object',
    properties: {
      file_path: {
        type: 'string',
        description: 'Path of the file to read (relative to workspace or canonical workspace path)'
      }
    },
    required: ['file_path']
  };

  async execute(args: { file_path: string }, context: ToolExecutionContext): Promise<ToolResult> {
    const startTime = Date.now();
    try {
      const resolvedPath = path.isAbsolute(args.file_path)
        ? args.file_path
        : path.resolve(context.workspaceRoot, args.file_path);

      if (!fs.existsSync(resolvedPath)) {
        return {
          success: false,
          error: `File not found: ${args.file_path}`,
          executionTimeMs: Date.now() - startTime
        };
      }

      const stat = fs.statSync(resolvedPath);
      if (stat.isDirectory()) {
        return {
          success: false,
          error: `Target is a directory, not a file: ${args.file_path}`,
          executionTimeMs: Date.now() - startTime
        };
      }

      const maxBytes = 512 * 1024; // 512 KB
      if (stat.size > maxBytes) {
        return {
          success: false,
          error: `File size exceeds safety limit (${stat.size} bytes > ${maxBytes} bytes). Large files must be inspected selectively.`,
          executionTimeMs: Date.now() - startTime
        };
      }

      const content = fs.readFileSync(resolvedPath, 'utf-8');
      const lines = content.split('\n').length;

      return {
        success: true,
        data: {
          content,
          lines,
          sizeBytes: stat.size
        },
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: any) {
      return {
        success: false,
        error: `Failed to read file: ${err.message}`,
        executionTimeMs: Date.now() - startTime
      };
    }
  }
}
