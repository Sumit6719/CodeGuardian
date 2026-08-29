import {
  IsolationLevel,
  IsolationPolicy,
  IsolationResult
} from './isolationTypes.js';
import {
  CommandProposal,
  ProcessResult,
  CapabilityGrant
} from '../../core/types.js';
import { ParsedCommand } from '../../execution/commandParser.js';

export interface IIsolationEnvironment {
  readonly id: string;
  readonly providerName: string;
  readonly isolationLevel: IsolationLevel;

  execute(
    proposal: CommandProposal,
    parsed: ParsedCommand,
    capability: CapabilityGrant
  ): Promise<ProcessResult>;

  destroy(): Promise<void>;
  isAlive(): boolean;
}

export interface IIsolationProvider {
  readonly name: string;
  readonly isolationLevel: IsolationLevel;

  isAvailable(): Promise<boolean>;

  createEnvironment(
    policy: IsolationPolicy,
    capability: CapabilityGrant
  ): Promise<IIsolationEnvironment>;
}
