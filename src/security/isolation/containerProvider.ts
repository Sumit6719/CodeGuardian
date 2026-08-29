import { execFile, spawn, ChildProcess } from 'child_process';
import path from 'path';
import fs from 'fs';
import {
  IIsolationProvider,
  IIsolationEnvironment
} from './isolationProvider.interface.js';
import {
  IsolationLevel,
  IsolationPolicy
} from './isolationTypes.js';
import {
  CommandProposal,
  ProcessResult,
  CapabilityGrant
} from '../../core/types.js';
import { ParsedCommand } from '../../execution/commandParser.js';

export class ContainerIsolationEnvironment implements IIsolationEnvironment {
  readonly id: string;
  readonly providerName = 'container-provider';
  readonly isolationLevel: IsolationLevel = 'CONTAINER';

  private readonly policy: IsolationPolicy;
  private readonly workspaceRoot: string;
  private alive = true;
  private activeContainerId: string | null = null;

  constructor(id: string, policy: IsolationPolicy, workspaceRoot: string) {
    this.id = id;
    this.policy = policy;
    this.workspaceRoot = workspaceRoot;
  }

  isAlive(): boolean {
    return this.alive;
  }

  /**
   * Executes a command inside an isolated Docker container using a direct,
   * dedicated trusted CLI launcher (never recursively calling governed execute_command tool).
   */
  async execute(
    proposal: CommandProposal,
    parsed: ParsedCommand,
    capability: CapabilityGrant
  ): Promise<ProcessResult> {
    if (!this.alive) {
      throw new Error(`ContainerIsolationEnvironment ${this.id} is destroyed.`);
    }

    const startTime = Date.now();
    const containerName = `cg_sandbox_${this.id}_${Date.now()}`;
    this.activeContainerId = containerName;

    // Build docker run CLI arguments
    const dockerArgs: string[] = [
      'run',
      '--name', containerName,
      '--rm',
      '--read-only',
      '--cap-drop=ALL'
    ];

    // Network policy mode mapping
    if (this.policy.networkPolicy.mode === 'NONE') {
      dockerArgs.push('--network', 'none');
    } else if (this.policy.networkPolicy.mode === 'ALLOWLIST' || this.policy.networkPolicy.mode === 'FULL') {
      dockerArgs.push('--network', 'host');
    }

    // Resource limits
    const limits = this.policy.resourceLimits;
    if (limits.maxMemoryMb) {
      dockerArgs.push(`--memory=${limits.maxMemoryMb}m`);
    }
    if (limits.maxCpuPercent) {
      const cpus = (limits.maxCpuPercent / 100).toFixed(2);
      dockerArgs.push(`--cpus=${cpus}`);
    }
    if (limits.maxProcesses) {
      dockerArgs.push(`--pids-limit=${limits.maxProcesses}`);
    }

    // Mount workspace root as READ-ONLY
    dockerArgs.push('-v', `${this.workspaceRoot}:${this.workspaceRoot}:ro`);

    // Mount allowed write paths as READ-WRITE
    for (const writePath of this.policy.filesystemPolicy.allowedWritePaths) {
      if (fs.existsSync(writePath)) {
        dockerArgs.push('-v', `${writePath}:${writePath}:rw`);
      }
    }

    // Set working directory
    const workingDir = proposal.workingDirectory || this.workspaceRoot;
    dockerArgs.push('-w', workingDir);

    // Image & command
    dockerArgs.push('node:20-alpine');
    dockerArgs.push(parsed.executable, ...parsed.args);

    return new Promise<ProcessResult>((resolve) => {
      let stdoutData = '';
      let stderrData = '';
      let timedOut = false;

      // Direct trusted host execution of docker binary
      const child: ChildProcess = spawn('docker', dockerArgs, {
        stdio: ['ignore', 'pipe', 'pipe']
      });

      const timeoutMs = limits.maxExecutionTimeMs || 60000;
      const timeoutTimer = setTimeout(() => {
        timedOut = true;
        // Force-kill container directly via trusted host docker kill
        execFile('docker', ['kill', containerName], () => {});
      }, timeoutMs);

      if (child.stdout) {
        child.stdout.on('data', (chunk) => {
          stdoutData += chunk.toString('utf-8');
        });
      }

      if (child.stderr) {
        child.stderr.on('data', (chunk) => {
          stderrData += chunk.toString('utf-8');
        });
      }

      child.on('error', (err) => {
        clearTimeout(timeoutTimer);
        this.activeContainerId = null;
        resolve({
          command: proposal.command,
          exitCode: null,
          signal: 'SIGFAIL',
          stdout: stdoutData,
          stderr: `Container launcher execution error: ${err.message}`,
          timedOut: false,
          durationMs: Date.now() - startTime,
          decision: 'ALLOW'
        });
      });

      child.on('exit', (code, signal) => {
        clearTimeout(timeoutTimer);
        this.activeContainerId = null;
        resolve({
          command: proposal.command,
          exitCode: code,
          signal: signal,
          stdout: stdoutData,
          stderr: stderrData,
          timedOut,
          durationMs: Date.now() - startTime,
          decision: 'ALLOW'
        });
      });
    });
  }

  async destroy(): Promise<void> {
    this.alive = false;
    if (this.activeContainerId) {
      const containerName = this.activeContainerId;
      this.activeContainerId = null;
      await new Promise<void>((resolve) => {
        execFile('docker', ['rm', '-f', containerName], () => resolve());
      });
    }
  }
}

export class ContainerIsolationProvider implements IIsolationProvider {
  readonly name = 'container-provider';
  readonly isolationLevel: IsolationLevel = 'CONTAINER';

  /**
   * Dynamically checks if Docker container runtime is available on the host.
   */
  async isAvailable(): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      execFile('docker', ['info'], { timeout: 3000 }, (error) => {
        resolve(!error);
      });
    });
  }

  async createEnvironment(
    policy: IsolationPolicy,
    capability: CapabilityGrant
  ): Promise<IIsolationEnvironment> {
    const available = await this.isAvailable();
    if (!available) {
      throw new Error(`ContainerIsolationProvider is unavailable: Docker runtime daemon is not responsive or installed.`);
    }

    const envId = `cnt_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    return new ContainerIsolationEnvironment(envId, policy, capability.workspaceRoot);
  }
}
