export type IsolationLevel =
  | 'NONE'
  | 'PROCESS'
  | 'FILESYSTEM'
  | 'NETWORK'
  | 'CONTAINER'
  | 'FULL';

export type NetworkPolicyMode =
  | 'NONE'
  | 'ALLOWLIST'
  | 'FULL';

export interface NetworkPolicy {
  readonly mode: NetworkPolicyMode;
  readonly allowedHosts?: readonly string[];
  readonly allowedPorts?: readonly number[];
}

export interface ResourceLimits {
  readonly maxExecutionTimeMs: number;
  readonly maxOutputBytes: number;
  readonly maxMemoryMb?: number;
  readonly maxCpuPercent?: number;
  readonly maxProcesses?: number;
  readonly maxFileChangeVolumeBytes?: number;
}

export type PathClassification =
  | 'OBSERVED'
  | 'ISOLATED'
  | 'EXCLUDED'
  | 'UNCONTROLLED';

export interface FilesystemIsolationPolicy {
  readonly mode: 'READ_ONLY' | 'RESTRICTED_WRITE' | 'FULL_WRITE';
  readonly allowedWritePaths: readonly string[];
  readonly deniedPaths: readonly string[];
  readonly pathTaxonomy?: Map<string, PathClassification>;
}

export interface IsolationPolicy {
  readonly requiredLevel: IsolationLevel;
  readonly networkPolicy: NetworkPolicy;
  readonly resourceLimits: ResourceLimits;
  readonly filesystemPolicy: FilesystemIsolationPolicy;
  readonly processLimits?: {
    readonly maxProcesses?: number;
  };
}

export interface IsolationResult {
  readonly success: boolean;
  readonly environmentId?: string;
  readonly level: IsolationLevel;
  readonly providerName: string;
  readonly error?: string;
}

/**
 * Numeric ordering helper for deterministic isolation strength comparisons.
 * NONE (0) < PROCESS (1) < FILESYSTEM (2) < NETWORK (3) < CONTAINER (4) < FULL (5)
 */
export const ISOLATION_LEVEL_WEIGHTS: Record<IsolationLevel, number> = {
  NONE: 0,
  PROCESS: 1,
  FILESYSTEM: 2,
  NETWORK: 3,
  CONTAINER: 4,
  FULL: 5
};

export function meetsIsolationRequirement(actual: IsolationLevel, required: IsolationLevel): boolean {
  return ISOLATION_LEVEL_WEIGHTS[actual] >= ISOLATION_LEVEL_WEIGHTS[required];
}
