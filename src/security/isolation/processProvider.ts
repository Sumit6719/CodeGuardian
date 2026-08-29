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
import { SecureProcessExecutor } from '../../execution/processExecutor.js';
import { PathGuard } from '../pathGuard.js';

export class ProcessIsolationEnvironment implements IIsolationEnvironment {
  readonly id: string;
  readonly providerName = 'process-provider';
  readonly isolationLevel: IsolationLevel = 'PROCESS';

  private readonly policy: IsolationPolicy;
  private readonly workspaceRoot: string;
  private readonly processExecutor: SecureProcessExecutor;
  private alive = true;

  constructor(id: string, policy: IsolationPolicy, workspaceRoot: string) {
    this.id = id;
    this.policy = policy;
    this.workspaceRoot = workspaceRoot;
    const pathGuard = new PathGuard(workspaceRoot);
    this.processExecutor = new SecureProcessExecutor(pathGuard, {
      timeoutMs: policy.resourceLimits.maxExecutionTimeMs,
      maxStdoutBytes: policy.resourceLimits.maxOutputBytes,
      maxStderrBytes: policy.resourceLimits.maxOutputBytes
    });
  }

  isAlive(): boolean {
    return this.alive;
  }

  async execute(
    proposal: CommandProposal,
    parsed: ParsedCommand,
    capability: CapabilityGrant
  ): Promise<ProcessResult> {
    if (!this.alive) {
      throw new Error(`ProcessIsolationEnvironment ${this.id} is destroyed.`);
    }

    const result = await this.processExecutor.execute(proposal, parsed, 'ALLOW', capability);
    return {
      ...result,
      isolationLevel: this.isolationLevel,
      sandboxId: this.id
    } as any;
  }

  async destroy(): Promise<void> {
    this.alive = false;
  }
}

export class ProcessIsolationProvider implements IIsolationProvider {
  readonly name = 'process-provider';
  readonly isolationLevel: IsolationLevel = 'PROCESS';

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async createEnvironment(
    policy: IsolationPolicy,
    capability: CapabilityGrant
  ): Promise<IIsolationEnvironment> {
    const envId = `proc_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    return new ProcessIsolationEnvironment(envId, policy, capability.workspaceRoot);
  }
}
