import fs from 'fs';
import path from 'path';
import { ITool, ToolExecutionContext, ToolSchema } from '../tool.interface.js';
import { OperationType, ToolResult } from '../../core/types.js';

export class ListFilesTool implements ITool {
  readonly name = 'list_files';
  readonly description = 'List files in a directory within the workspace. Automatically skips node_modules, build, and git folders.';
  readonly operation: OperationType = 'LIST';

  readonly parameters: ToolSchema = {
    type: 'object',
    properties: {
      directory: {
        type: 'string',
        description: 'Directory path to scan (relative to workspace or canonical workspace path)'
      }
    },
    required: ['directory']
  };

  async execute(args: { directory: string }, context: ToolExecutionContext): Promise<ToolResult> {
    const startTime = Date.now();
    try {
      const targetDir = args.directory || context.workspaceRoot;
      const resolvedDir = path.isAbsolute(targetDir)
        ? targetDir
        : path.resolve(context.workspaceRoot, targetDir);

      if (!fs.existsSync(resolvedDir)) {
        return {
          success: false,
          error: `Directory not found: ${args.directory}`,
          executionTimeMs: Date.now() - startTime
        };
      }

      const files: string[] = [];
      const ignoredFolders = new Set(['node_modules', 'dist', 'build', '.git', '.codeguardian', '.vscode']);
      const maxFiles = 300;
      const maxDepth = 8;

      const scan = (currentDir: string, depth: number) => {
        if (depth > maxDepth || files.length >= maxFiles) return;

        const entries = fs.readdirSync(currentDir, { withFileTypes: true });

        for (const entry of entries) {
          if (files.length >= maxFiles) break;

          if (ignoredFolders.has(entry.name)) {
            continue;
          }

          const fullPath = path.join(currentDir, entry.name);

          if (entry.isDirectory()) {
            scan(fullPath, depth + 1);
          } else if (entry.isFile()) {
            const relPath = path.relative(context.workspaceRoot, fullPath).replace(/\\/g, '/');
            files.push(relPath);
          }
        }
      };

      scan(resolvedDir, 0);

      return {
        success: true,
        data: {
          files,
          total: files.length,
          truncated: files.length >= maxFiles
        },
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: any) {
      return {
        success: false,
        error: `Failed to list files: ${err.message}`,
        executionTimeMs: Date.now() - startTime
      };
    }
  }
}
