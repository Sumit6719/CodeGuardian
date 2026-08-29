import { spawn, exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import {
  CommandProposal,
  ProcessResult,
  CommandDecision,
  CapabilityGrant,
  ProcessExecutionContext
} from '../core/types.js';
import { PathGuard } from '../security/pathGuard.js';
import { PathTraversalError } from '../core/errors.js';
import { ParsedCommand } from './commandParser.js';

export interface ProcessExecutorOptions {
  readonly timeoutMs?: number;
  readonly maxStdoutBytes?: number;
  readonly maxStderrBytes?: number;
  readonly allowedEnvKeys?: readonly string[];
}

export class SecureProcessExecutor {
  private readonly pathGuard: PathGuard;
  private readonly defaultTimeoutMs: number;
  private readonly defaultMaxStdoutBytes: number;
  private readonly defaultMaxStderrBytes: number;
  private readonly allowedEnvKeys: Set<string>;
  private readonly activeContexts = new Map<number, ProcessExecutionContext>();

  constructor(
    pathGuard: PathGuard,
    options?: ProcessExecutorOptions
  ) {
    this.pathGuard = pathGuard;
    this.defaultTimeoutMs = options?.timeoutMs ?? 60000; // 60s
    this.defaultMaxStdoutBytes = options?.maxStdoutBytes ?? 100 * 1024; // 100KB
    this.defaultMaxStderrBytes = options?.maxStderrBytes ?? 100 * 1024; // 100KB

    const envKeys = options?.allowedEnvKeys || [
      'PATH', 'APPDATA', 'LOCALAPPDATA', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP',
      'USERPROFILE', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'NODE_PATH', 'TERM',
      'OS', 'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS', 'SYSTEMDRIVE', 'PATHEXT'
    ];
    this.allowedEnvKeys = new Set(envKeys.map(k => k.toUpperCase()));
  }

  /**
   * Constructs a sanitized environment map, scrubbing secrets and parent credentials.
   */
  getSanitizedEnv(customEnv?: Record<string, string>): Record<string, string> {
    const sanitized: Record<string, string> = {};

    // Copy whitelisted env variables from parent
    for (const key of Object.keys(process.env)) {
      const uKey = key.toUpperCase();
      if (this.allowedEnvKeys.has(uKey)) {
        const val = process.env[key];
        if (val !== undefined && !this.isSensitive(key, val)) {
          sanitized[key] = val;
        }
      }
    }

    // Merge custom env variables from the command if safe
    if (customEnv) {
      for (const [key, val] of Object.entries(customEnv)) {
        if (!this.isSensitive(key, val)) {
          sanitized[key] = val;
        }
      }
    }

    return sanitized;
  }

  /**
   * Helper to detect sensitive keys or values (API keys, secrets)
   */
  private isSensitive(key: string, value: string): boolean {
    const uKey = key.toUpperCase();
    const sensitiveKeys = [
      'KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'API', 'AUTH', 'PWD', 'PASS',
      'CREDENTIALS', 'JWT', 'SALT', 'CERT', 'PASSPHRASE', 'SSH'
    ];
    if (sensitiveKeys.some(s => uKey.includes(s))) {
      return true;
    }
    // General secret shape heuristic check
    if (/^[a-zA-Z0-9_\-]{32,128}$/.test(value) && (uKey.includes('API') || uKey.includes('SEC') || uKey.includes('KEY'))) {
      return true;
    }
    return false;
  }

  /**
   * Validates target execution options against capability grants
   */
  private validateCapability(grant: CapabilityGrant, requestedDir: string): { readonly valid: boolean; readonly reason?: string } {
    if (Date.now() > grant.expiresAt) {
      return { valid: false, reason: 'Capability grant has expired.' };
    }
    if (grant.workspaceRoot.replace(/\\/g, '/').toLowerCase() !== this.pathGuard.getWorkspaceRoot().toLowerCase()) {
      return { valid: false, reason: 'Capability grant workspace root mismatch.' };
    }
    if (!grant.processExecution) {
      return { valid: false, reason: 'Capability grant does not permit process execution.' };
    }

    const normalizedReqDir = requestedDir.replace(/\\/g, '/').toLowerCase();
    const isAllowed = grant.allowedPaths.some(p => {
      const normAllowed = p.replace(/\\/g, '/').toLowerCase();
      return normalizedReqDir.startsWith(normAllowed);
    });

    if (!isAllowed) {
      return { valid: false, reason: `Path "${requestedDir}" is not in the allowed paths list.` };
    }

    const isDenied = grant.deniedPaths.some(p => {
      const normDenied = p.replace(/\\/g, '/').toLowerCase();
      return normalizedReqDir.startsWith(normDenied);
    });

    if (isDenied) {
      return { valid: false, reason: `Path "${requestedDir}" is explicitly denied.` };
    }

    return { valid: true };
  }

  /**
   * Executes a proposed command in a secure, bounded subprocess environment.
   */
  async execute(
    proposal: CommandProposal,
    parsed: ParsedCommand,
    decision: CommandDecision,
    capability?: CapabilityGrant
  ): Promise<ProcessResult> {
    const startTime = Date.now();

    // 1. Enforce Workspace Boundary for Working Directory
    const workingDir = proposal.workingDirectory || this.pathGuard.getWorkspaceRoot();
    const pathCheck = this.pathGuard.validate(workingDir);

    if (!pathCheck.allowed) {
      throw new PathTraversalError(
        `Command execution directory resolves outside workspace root: ${workingDir}`,
        workingDir,
        this.pathGuard.getWorkspaceRoot()
      );
    }

    const canonicalWorkingDir = pathCheck.canonicalPath;
    if (!fs.existsSync(canonicalWorkingDir)) {
      throw new Error(`Execution directory does not exist: ${canonicalWorkingDir}`);
    }

    // 2. Validate Capability Grant
    if (capability) {
      const capValidation = this.validateCapability(capability, canonicalWorkingDir);
      if (!capValidation.valid) {
        return {
          command: proposal.command,
          exitCode: null,
          signal: 'SIGBLOCK',
          stdout: '',
          stderr: `Capability violation: ${capValidation.reason}`,
          timedOut: false,
          durationMs: 0,
          decision: 'BLOCK'
        };
      }
    }

    if (decision === 'BLOCK') {
      return {
        command: proposal.command,
        exitCode: null,
        signal: 'SIGBLOCK',
        stdout: '',
        stderr: 'Execution BLOCKED by security policy.',
        timedOut: false,
        durationMs: 0,
        decision
      };
    }

    // Configure limits based on capability or defaults
    const timeoutMs = capability ? capability.maxExecutionTimeMs : this.defaultTimeoutMs;
    const maxStdoutBytes = capability ? capability.maxOutputBytes : this.defaultMaxStdoutBytes;
    const maxStderrBytes = capability ? capability.maxOutputBytes : this.defaultMaxStderrBytes;

    // Build execution environment
    const sanitizedEnv = this.getSanitizedEnv(parsed.env);

    return new Promise((resolve) => {
      let stdoutData = '';
      let stderrData = '';
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let timedOut = false;
      let stdoutTruncated = false;
      let stderrTruncated = false;

      let executablePath = parsed.executable;
      let spawnArgs = [...parsed.args];
      if (process.platform === 'win32') {
        const lowerExe = executablePath.toLowerCase();
        if (lowerExe === 'npm' || lowerExe === 'npx' || lowerExe === 'yarn') {
          executablePath = 'cmd.exe';
          spawnArgs = ['/d', '/s', '/c', `${lowerExe}.cmd`, ...parsed.args];
        } else if (lowerExe === 'git') {
          executablePath += '.exe';
        }
      }

      // Spawn process inside a new process group (detached: true) to allow Unix group termination
      const child = spawn(executablePath, spawnArgs, {
        cwd: canonicalWorkingDir,
        env: sanitizedEnv,
        shell: false,
        detached: process.platform !== 'win32'
      });

      if (child.pid) {
        const descendants = new Set<number>();
        const execContext: ProcessExecutionContext = {
          pid: child.pid,
          processGroupId: process.platform !== 'win32' ? child.pid : undefined,
          startedAt: startTime,
          workspaceRoot: canonicalWorkingDir,
          command: proposal.command,
          descendants
        };
        this.activeContexts.set(child.pid, execContext);
      }

      // Timeout handler
      const timeoutTimer = setTimeout(() => {
        timedOut = true;
        this.killProcessTree(child.pid);
      }, timeoutMs);

      // Handle output streams with buffers and truncation thresholds
      if (child.stdout) {
        child.stdout.on('data', (chunk: Buffer) => {
          if (stdoutTruncated) return;
          
          const chunkStr = chunk.toString('utf-8');
          stdoutBytes += Buffer.byteLength(chunkStr, 'utf-8');

          if (stdoutBytes > maxStdoutBytes) {
            stdoutTruncated = true;
            stdoutData += chunkStr.slice(0, maxStdoutBytes - (stdoutBytes - chunkStr.length));
            stdoutData += `\n... [STDOUT TRUNCATED AT ${maxStdoutBytes} BYTES BY CODEGUARDIAN] ...\n`;
          } else {
            stdoutData += chunkStr;
          }
        });
      }

      if (child.stderr) {
        child.stderr.on('data', (chunk: Buffer) => {
          if (stderrTruncated) return;

          const chunkStr = chunk.toString('utf-8');
          stderrBytes += Buffer.byteLength(chunkStr, 'utf-8');

          if (stderrBytes > maxStderrBytes) {
            stderrTruncated = true;
            stderrData += chunkStr.slice(0, maxStderrBytes - (stderrBytes - chunkStr.length));
            stderrData += `\n... [STDERR TRUNCATED AT ${maxStderrBytes} BYTES BY CODEGUARDIAN] ...\n`;
          } else {
            stderrData += chunkStr;
          }
        });
      }

      child.on('error', (err: any) => {
        clearTimeout(timeoutTimer);
        if (child.pid) {
          this.activeContexts.delete(child.pid);
        }
        resolve({
          command: proposal.command,
          exitCode: null,
          signal: null,
          stdout: stdoutData,
          stderr: stderrData + `\nExecution Error: ${err.message}`,
          timedOut: false,
          durationMs: Date.now() - startTime,
          decision
        });
      });

      child.on('exit', (code: number | null, signal: string | null) => {
        clearTimeout(timeoutTimer);
        if (child.pid) {
          this.activeContexts.delete(child.pid);
        }
        resolve({
          command: proposal.command,
          exitCode: code,
          signal: signal,
          stdout: stdoutData,
          stderr: stderrData,
          timedOut,
          durationMs: Date.now() - startTime,
          decision
        });
      });
    });
  }

  /**
   * Platform-specific process tree termination to prevent orphan leaks.
   * On Unix, uses negative PID (-pid) to terminate the entire process group.
   * On Windows, uses taskkill tree termination (/T).
   */
  private killProcessTree(pid: number | undefined): void {
    if (!pid) return;

    try {
      if (process.platform === 'win32') {
        exec(`taskkill /F /T /PID ${pid}`, () => {});
      } else {
        // Kill group using negative PID
        process.kill(-pid, 'SIGKILL');
      }
    } catch {
      // ignore
    }
  }
}
