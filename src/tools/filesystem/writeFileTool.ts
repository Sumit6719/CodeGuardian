import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ITool, ToolExecutionContext, ToolSchema } from '../tool.interface.js';
import { OperationType, ToolResult } from '../../core/types.js';

export class WriteFileTool implements ITool {
  readonly name = 'write_file';
  readonly description = 'Atomically write content to a file in the workspace with automatic snapshot backup and integrity verification.';
  readonly operation: OperationType = 'WRITE';

  readonly parameters: ToolSchema = {
    type: 'object',
    properties: {
      file_path: {
        type: 'string',
        description: 'Path of the file to write (relative to workspace or canonical path)'
      },
      content: {
        type: 'string',
        description: 'The complete new content to write to the file'
      }
    },
    required: ['file_path', 'content']
  };

  async execute(args: { file_path: string; content: string }, context: ToolExecutionContext): Promise<ToolResult> {
    const startTime = Date.now();
    let tempFilePath: string | null = null;

    try {
      if (typeof args.content !== 'string') {
        return {
          success: false,
          error: 'Write content must be a valid string.',
          executionTimeMs: Date.now() - startTime
        };
      }

      const resolvedPath = path.isAbsolute(args.file_path)
        ? args.file_path
        : path.resolve(context.workspaceRoot, args.file_path);

      const targetDir = path.dirname(resolvedPath);
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }

      // 1. Pre-write syntax verification (isolated AST validation)
      if (context.syntaxVerifier) {
        const syntaxResult = context.syntaxVerifier.verify(resolvedPath, args.content);
        if (syntaxResult.status === 'FAIL') {
          const errMessages = syntaxResult.errors
            .map(e => `line ${e.line}:${e.column} - ${e.message}`)
            .join('; ');
          return {
            success: false,
            error: `SYNTAX_VERIFICATION_FAILED: Proposed content contains syntax errors: ${errMessages}`,
            executionTimeMs: Date.now() - startTime
          };
        }
      }

      // 2. Create pre-change snapshot (reads existing content and computes beforeHash)
      const snapshot = context.snapshotManager.createSnapshot(resolvedPath);

      // 3. Calculate target afterHash
      const afterHash = crypto.createHash('sha256').update(args.content, 'utf-8').digest('hex');

      // 4 & 5. Atomic Write via sibling temp file
      const randomSuffix = Math.random().toString(36).slice(2, 8);
      tempFilePath = path.join(targetDir, `.${path.basename(resolvedPath)}.cg_tmp.${Date.now()}.${randomSuffix}`);

      fs.writeFileSync(tempFilePath, args.content, 'utf-8');

      // Replace target atomically
      const siblingTempPath = tempFilePath;
      try {
        fs.renameSync(siblingTempPath, resolvedPath);
        tempFilePath = null; // Successfully moved
      } catch (renameErr) {
        // Fallback for Windows file locks: copy and delete
        fs.copyFileSync(siblingTempPath, resolvedPath);
        try {
          fs.unlinkSync(siblingTempPath);
        } catch {
          // ignore temp cleanup error
        }
        tempFilePath = null;
      }

      // 6. Post-write integrity & syntax verification
      const verifyResult = context.integrityVerifier.verify(resolvedPath, args.content, snapshot);
      let postSyntaxValid = true;
      let postSyntaxErrors: string[] = [];

      if (context.syntaxVerifier && verifyResult.valid) {
        const writtenContent = fs.readFileSync(resolvedPath, 'utf-8');
        const postSyntax = context.syntaxVerifier.verify(resolvedPath, writtenContent);
        if (postSyntax.status === 'FAIL') {
          postSyntaxValid = false;
          postSyntaxErrors = postSyntax.errors.map(e => `line ${e.line}:${e.column} - ${e.message}`);
        }
      }

      if (!verifyResult.valid || !postSyntaxValid) {
        // Trigger verified rollback
        if (context.rollbackManager) {
          context.rollbackManager.rollback(snapshot);
        } else {
          context.snapshotManager.restore(snapshot.snapshotId);
        }

        const allErrors = [...verifyResult.errors, ...postSyntaxErrors];
        return {
          success: false,
          error: `Integrity/syntax check failed after write: ${allErrors.join(', ')}. Original state automatically rolled back.`,
          executionTimeMs: Date.now() - startTime
        };
      }

      return {
        success: true,
        data: {
          filePath: args.file_path,
          canonicalPath: resolvedPath,
          snapshotId: snapshot.snapshotId,
          beforeHash: snapshot.originalHash,
          afterHash,
          bytesWritten: Buffer.byteLength(args.content, 'utf-8')
        },
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: any) {
      // Clean up temp file if still present
      if (tempFilePath && fs.existsSync(tempFilePath)) {
        try {
          fs.unlinkSync(tempFilePath);
        } catch {
          // ignore
        }
      }

      return {
        success: false,
        error: `Atomic write failed: ${err.message}`,
        executionTimeMs: Date.now() - startTime
      };
    }
  }
}
