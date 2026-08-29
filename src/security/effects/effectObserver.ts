import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { PathGuard } from '../pathGuard.js';
import { 
  ObservedEffects, 
  FilesystemEffect, 
  NetworkEffect, 
  ProcessEffect 
} from './effectTypes.js';

export interface FileMetadata {
  readonly size: number;
  readonly mtime: number;
  readonly hash: string | null;
}

export interface WorkspaceState {
  readonly files: Map<string, FileMetadata>;
  readonly directories: Set<string>;
}

export interface ObserverConfig {
  readonly maxDepth?: number;
  readonly maxFiles?: number;
  readonly hashFileLimitBytes?: number;
  /** Absolute file paths that must never be snapshotted or detected as effects (e.g. evidence ledger, audit log) */
  readonly excludedFiles?: readonly string[];
}

export class EffectObserver {
  private readonly workspaceRoot: string;
  private readonly pathGuard: PathGuard;
  private readonly config: Required<ObserverConfig>;
  private readonly excludedFiles: Set<string>;

  constructor(workspaceRoot: string, config?: ObserverConfig) {
    this.workspaceRoot = path.resolve(workspaceRoot);
    this.pathGuard = new PathGuard(this.workspaceRoot);
    this.config = {
      maxDepth: config?.maxDepth ?? 10,
      maxFiles: config?.maxFiles ?? 2000,
      hashFileLimitBytes: config?.hashFileLimitBytes ?? 5 * 1024 * 1024, // 5MB
      excludedFiles: config?.excludedFiles ?? []
    };
    // Resolve all excluded paths to canonical form to enable reliable comparison
    this.excludedFiles = new Set(
      (config?.excludedFiles ?? []).map(f => {
        try { return fs.realpathSync(f); } catch { return path.resolve(f); }
      })
    );
  }

  /**
   * Deterministically computes the SHA-256 hash of a file's content
   */
  private computeHash(filePath: string): string | null {
    try {
      const content = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch {
      return null;
    }
  }

  /**
   * Captures the full filesystem state of the workspace recursively
   */
  captureState(): WorkspaceState {
    const files = new Map<string, FileMetadata>();
    const directories = new Set<string>();
    let fileCount = 0;

    const traverse = (dirPath: string, depth: number): void => {
      if (depth > this.config.maxDepth) {
        return;
      }

      let entries: fs.Dirent[] = [];
      try {
        entries = fs.readdirSync(dirPath, { withFileTypes: true });
      } catch {
        // Safe check: if we cannot read, skip
        return;
      }

      for (const entry of entries) {
        if (fileCount >= this.config.maxFiles) {
          break;
        }

        const fullPath = path.join(dirPath, entry.name);
        let canonicalPath = '';
        
        try {
          canonicalPath = fs.realpathSync(fullPath);
        } catch {
          // If realpath fails (e.g. broken symlink), skip
          continue;
        }

        // Safety: Verify the canonical path remains within workspace boundaries
        if (!canonicalPath.startsWith(this.workspaceRoot)) {
          // Symlink points outside workspace - do not follow or record to prevent traversal escapes
          continue;
        }

        let stat: fs.Stats;
        try {
          stat = fs.lstatSync(fullPath);
        } catch {
          continue;
        }

        if (stat.isSymbolicLink()) {
          // Resolve symlink target stat
          try {
            stat = fs.statSync(fullPath);
          } catch {
            continue;
          }
        }

        if (stat.isDirectory()) {
          const baseName = path.basename(canonicalPath);
          if (baseName === '.git' || baseName === 'node_modules' || baseName === '.codeguardian') {
            continue;
          }
          directories.add(canonicalPath);
          traverse(canonicalPath, depth + 1);
        } else if (stat.isFile()) {
          // Skip infrastructure files explicitly excluded (evidence ledger, audit log, etc.)
          if (this.excludedFiles.has(canonicalPath)) {
            continue;
          }
          fileCount++;
          let fileHash: string | null = null;
          
          if (stat.size <= this.config.hashFileLimitBytes) {
            fileHash = this.computeHash(canonicalPath);
          }

          files.set(canonicalPath, {
            size: stat.size,
            mtime: stat.mtimeMs,
            hash: fileHash
          });
        }
      }
    };

    directories.add(this.workspaceRoot);
    traverse(this.workspaceRoot, 1);

    return { files, directories };
  }

  /**
   * Computes the difference between pre-execution and post-execution state
   */
  detectEffects(
    preState: WorkspaceState,
    postState: WorkspaceState,
    observedProcesses: ProcessEffect[] = [],
    observedNetwork: NetworkEffect[] = []
  ): ObservedEffects {
    const filesystem: FilesystemEffect[] = [];
    const timestamp = Date.now();

    // 1. Detect file deletions
    for (const [filePath, metadata] of preState.files.entries()) {
      if (!postState.files.has(filePath)) {
        filesystem.push({
          type: 'FILE_DELETE',
          target: filePath,
          timestamp,
          sizeBytes: metadata.size,
          hash: metadata.hash
        });
      }
    }

    // 2. Detect file creations and modifications
    for (const [filePath, postMetadata] of postState.files.entries()) {
      const preMetadata = preState.files.get(filePath);

      if (!preMetadata) {
        filesystem.push({
          type: 'FILE_CREATE',
          target: filePath,
          timestamp,
          sizeBytes: postMetadata.size,
          hash: postMetadata.hash
        });
      } else {
        // Compare hash or size/mtime to determine modification
        const hashChanged = preMetadata.hash !== null && postMetadata.hash !== null && preMetadata.hash !== postMetadata.hash;
        const sizeOrMtimeChanged = preMetadata.size !== postMetadata.size || preMetadata.mtime !== postMetadata.mtime;

        if (hashChanged || (preMetadata.hash === null && sizeOrMtimeChanged)) {
          filesystem.push({
            type: 'FILE_WRITE',
            target: filePath,
            timestamp,
            sizeBytes: postMetadata.size,
            hash: postMetadata.hash
          });
        }
      }
    }

    // 3. Detect directory deletions
    for (const dirPath of preState.directories) {
      if (!postState.directories.has(dirPath)) {
        filesystem.push({
          type: 'DIR_DELETE',
          target: dirPath,
          timestamp
        });
      }
    }

    // 4. Detect directory creations
    for (const dirPath of postState.directories) {
      if (!preState.directories.has(dirPath)) {
        filesystem.push({
          type: 'DIR_CREATE',
          target: dirPath,
          timestamp
        });
      }
    }

    return {
      filesystem,
      processes: observedProcesses,
      network: observedNetwork
    };
  }
}
