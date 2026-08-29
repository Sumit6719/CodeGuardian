import fs from 'fs';
import path from 'path';

export interface WorkspaceSummary {
  rootPath: string;
  totalFiles: number;
  extensions: Record<string, number>;
  hasGit: boolean;
}

export class WorkspaceContext {
  private readonly rootPath: string;

  constructor(rootPath: string) {
    this.rootPath = path.resolve(rootPath);
  }

  getSummary(): WorkspaceSummary {
    const extensions: Record<string, number> = {};
    let totalFiles = 0;
    const ignoredFolders = new Set(['node_modules', 'dist', 'build', '.git', '.codeguardian']);

    const scan = (dir: string, depth: number) => {
      if (depth > 6) return;
      if (!fs.existsSync(dir)) return;

      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (ignoredFolders.has(entry.name)) continue;

        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          scan(fullPath, depth + 1);
        } else if (entry.isFile()) {
          totalFiles++;
          const ext = path.extname(entry.name).toLowerCase() || '[no_ext]';
          extensions[ext] = (extensions[ext] || 0) + 1;
        }
      }
    };

    scan(this.rootPath, 0);

    return {
      rootPath: this.rootPath,
      totalFiles,
      extensions,
      hasGit: fs.existsSync(path.join(this.rootPath, '.git'))
    };
  }
}
