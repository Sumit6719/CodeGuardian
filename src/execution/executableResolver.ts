import path from 'path';
import fs from 'fs';
import { ResolvedExecutable } from '../core/types.js';
import { PathGuard } from '../security/pathGuard.js';

export class ExecutableResolver {
  private readonly pathGuard: PathGuard;
  private readonly isWindows: boolean;

  constructor(pathGuard: PathGuard) {
    this.pathGuard = pathGuard;
    this.isWindows = process.platform === 'win32';
  }

  /**
   * Resolves a binary name to its absolute executable path and identifies its safety source.
   */
  resolve(requestedName: string): ResolvedExecutable {
    const workspaceRoot = this.pathGuard.getWorkspaceRoot();
    
    // Normalize executable name (handle relative/absolute path vs simple name)
    const isAbsolute = path.isAbsolute(requestedName);
    const isRelative = requestedName.startsWith('.') || requestedName.includes('/') || requestedName.includes('\\');

    let resolvedPath = '';
    let source: 'SYSTEM' | 'WORKSPACE' | 'UNKNOWN' = 'UNKNOWN';
    let trusted = false;

    if (isAbsolute || isRelative) {
      // It's a path. Resolve it canonically relative to workspace root if relative.
      const resolved = isAbsolute
        ? path.resolve(requestedName)
        : path.resolve(workspaceRoot, requestedName);

      // Check containment using PathGuard
      const pathCheck = this.pathGuard.validate(resolved);
      resolvedPath = pathCheck.canonicalPath || resolved;

      if (pathCheck.allowed) {
        source = 'WORKSPACE';
        trusted = false; // Binaries within workspace are NEVER trusted by default
      } else {
        // Outside workspace, check if in system path or unknown
        source = this.isSystemPath(resolvedPath) ? 'SYSTEM' : 'UNKNOWN';
        // Trusted if it's resolved under a known system directory and exists
        trusted = source === 'SYSTEM' && fs.existsSync(resolvedPath);
      }
    } else {
      // It's a simple name (e.g. "node", "npm", "git"). Search system PATH.
      const pathEnv = process.env.PATH || '';
      const pathDirs = pathEnv.split(this.isWindows ? ';' : ':');

      // System binaries could have extensions on Windows
      const extensions = this.isWindows ? ['.exe', '.cmd', '.bat', '.cmd.exe', ''] : [''];

      for (const dir of pathDirs) {
        if (!dir) continue;
        
        let found = false;
        for (const ext of extensions) {
          const candidate = path.join(dir, requestedName + ext);
          if (fs.existsSync(candidate)) {
            try {
              const realCandidate = fs.realpathSync(candidate);
              const pathCheck = this.pathGuard.validate(realCandidate);
              if (pathCheck.allowed) {
                // Resolved inside workspace
                resolvedPath = realCandidate;
                source = 'WORKSPACE';
                trusted = false;
                found = true;
                break;
              } else {
                resolvedPath = realCandidate;
                source = this.isSystemPath(realCandidate) ? 'SYSTEM' : 'UNKNOWN';
                trusted = source === 'SYSTEM';
                found = true;
                break;
              }
            } catch {
              // ignore realpath failure, check raw existence
              resolvedPath = path.resolve(candidate);
              source = this.isSystemPath(resolvedPath) ? 'SYSTEM' : 'UNKNOWN';
              trusted = source === 'SYSTEM';
              found = true;
              break;
            }
          }
        }
        if (found) {
          break;
        }
      }

      if (!resolvedPath) {
        resolvedPath = requestedName;
        source = 'UNKNOWN';
        trusted = false;
      }
    }

    return {
      requestedName,
      resolvedPath: resolvedPath.replace(/\\/g, '/'),
      trusted,
      source
    };
  }

  /**
   * Helper to check if a resolved absolute path resides in known system executable directories
   */
  private isSystemPath(absPath: string): boolean {
    const normalized = absPath.replace(/\\/g, '/').toLowerCase();
    const workspaceLower = this.pathGuard.getWorkspaceRoot().toLowerCase();
    
    // Invariant: anything inside the workspace can never be considered system
    if (normalized.startsWith(workspaceLower)) {
      return false;
    }

    if (this.isWindows) {
      const systemDirs = [
        'c:/windows',
        'c:/program files',
        'c:/program files (x86)',
      ];
      // Also allow directories that contain windows-specific pathing keys outside the user's workspace
      return systemDirs.some(dir => normalized.startsWith(dir)) || normalized.includes('/windows/') || normalized.includes('/system32/');
    } else {
      const systemDirs = [
        '/bin/', '/usr/bin/', '/usr/local/bin/', '/sbin/', '/usr/sbin/', '/usr/local/sbin/', '/opt/'
      ];
      return systemDirs.some(dir => normalized.startsWith(dir)) || normalized.startsWith('/usr/');
    }
  }
}
