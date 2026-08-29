import path from 'path';
import fs from 'fs';
import { PathGuardResult } from '../core/types.js';
import { PathTraversalError } from '../core/errors.js';

export class PathGuard {
  private readonly canonicalWorkspaceRoot: string;
  private readonly isWindows: boolean;

  constructor(workspaceRoot: string) {
    this.isWindows = process.platform === 'win32';
    
    // Resolve workspaceRoot canonically
    let root = path.resolve(workspaceRoot);
    if (fs.existsSync(root)) {
      try {
        root = fs.realpathSync(root);
      } catch {
        // Fallback to path.resolve if realpath fails
      }
    }
    this.canonicalWorkspaceRoot = this.normalizeSeparators(root);
  }

  getWorkspaceRoot(): string {
    return this.canonicalWorkspaceRoot;
  }

  /**
   * Evaluates a requested path against workspace boundaries.
   * Performs canonical resolution, symlink verification, and containment checks.
   */
  validate(targetPath: string): PathGuardResult {
    if (!targetPath || typeof targetPath !== 'string' || targetPath.trim() === '') {
      return {
        allowed: false,
        canonicalPath: '',
        relativePath: '',
        error: 'Path cannot be empty.'
      };
    }

    const trimmed = targetPath.trim();

    // Prevent explicit null byte injections
    if (trimmed.includes('\0')) {
      return {
        allowed: false,
        canonicalPath: '',
        relativePath: '',
        error: 'Null byte injection detected in path.'
      };
    }

    // Resolve target path relative to canonical workspace root if relative,
    // or as absolute if absolute.
    const resolvedPath = path.isAbsolute(trimmed)
      ? path.resolve(trimmed)
      : path.resolve(this.canonicalWorkspaceRoot, trimmed);

    let canonicalPath = this.normalizeSeparators(resolvedPath);

    // If path exists, check realpath (symlink resolution)
    if (fs.existsSync(canonicalPath)) {
      try {
        const realTarget = fs.realpathSync(canonicalPath);
        canonicalPath = this.normalizeSeparators(realTarget);
      } catch (err: any) {
        return {
          allowed: false,
          canonicalPath,
          relativePath: '',
          error: `Failed to resolve realpath: ${err.message}`
        };
      }
    } else {
      // If the target does not exist yet (e.g. creating a new file),
      // resolve the nearest existing ancestor to ensure symlink escape is not hiding in parent path
      let currentDir = path.dirname(canonicalPath);
      while (currentDir && currentDir !== path.dirname(currentDir)) {
        if (fs.existsSync(currentDir)) {
          try {
            const realParent = fs.realpathSync(currentDir);
            const normalizedRealParent = this.normalizeSeparators(realParent);
            if (!this.isContained(normalizedRealParent, this.canonicalWorkspaceRoot)) {
              return {
                allowed: false,
                canonicalPath,
                relativePath: '',
                error: `Path escapes workspace containment: Parent directory resolves outside workspace: ${normalizedRealParent}`
              };
            }
          } catch {
            // ignore and proceed
          }
          break;
        }
        currentDir = path.dirname(currentDir);
      }
    }

    // Final strict containment check
    const contained = this.isContained(canonicalPath, this.canonicalWorkspaceRoot);

    if (!contained) {
      return {
        allowed: false,
        canonicalPath,
        relativePath: '',
        error: `Path escapes workspace containment: ${canonicalPath}`
      };
    }

    // Compute relative path from workspace root
    const relativePath = path.relative(this.canonicalWorkspaceRoot, canonicalPath);

    return {
      allowed: true,
      canonicalPath,
      relativePath: this.normalizeSeparators(relativePath || '.')
    };
  }

  /**
   * Asserts path containment or throws a PathTraversalError
   */
  assertAllowed(targetPath: string): PathGuardResult {
    const result = this.validate(targetPath);
    if (!result.allowed) {
      throw new PathTraversalError(
        result.error || `Target path is outside workspace: ${targetPath}`,
        targetPath,
        this.canonicalWorkspaceRoot
      );
    }
    return result;
  }

  /**
   * Normalizes directory separators to forward slashes for cross-platform consistency
   */
  private normalizeSeparators(p: string): string {
    return p.replace(/\\/g, '/');
  }

  /**
   * Checks if target is equal to or a subpath of root
   */
  private isContained(target: string, root: string): boolean {
    const normTarget = this.isWindows ? target.toLowerCase() : target;
    const normRoot = this.isWindows ? root.toLowerCase() : root;

    if (normTarget === normRoot) {
      return true;
    }

    const prefix = normRoot.endsWith('/') ? normRoot : normRoot + '/';
    return normTarget.startsWith(prefix);
  }
}
