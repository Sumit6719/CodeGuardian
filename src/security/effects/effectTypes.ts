export type EffectType =
  | 'FILE_READ'
  | 'FILE_CREATE'
  | 'FILE_WRITE'
  | 'FILE_DELETE'
  | 'DIR_CREATE'
  | 'DIR_DELETE'
  | 'NET_CONNECT'
  | 'NET_LISTEN'
  | 'PROCESS_SPAWN'
  | 'ENV_WRITE';

export interface BaseEffect {
  readonly type: EffectType;
  readonly target: string;
  readonly timestamp: number;
}

export interface FilesystemEffect extends BaseEffect {
  readonly sizeBytes?: number;
  readonly hash?: string | null;
}

export interface NetworkEffect extends BaseEffect {
  readonly host: string;
  readonly port: number;
  readonly protocol: 'TCP' | 'UDP';
}

export interface ProcessEffect extends BaseEffect {
  readonly pid: number;
  readonly parentPid?: number;
  readonly commandLine: string;
}

export interface ObservedEffects {
  readonly filesystem: readonly FilesystemEffect[];
  readonly network: readonly NetworkEffect[];
  readonly processes: readonly ProcessEffect[];
}

export interface ExpectedEffects {
  readonly allowedPaths: readonly string[];
  readonly deniedPaths: readonly string[];
  readonly allowNetwork: boolean;
  readonly allowedProcesses: readonly string[];
}

/**
 * Deterministic type guards
 */
export function isFilesystemEffect(effect: BaseEffect): effect is FilesystemEffect {
  return [
    'FILE_READ',
    'FILE_CREATE',
    'FILE_WRITE',
    'FILE_DELETE',
    'DIR_CREATE',
    'DIR_DELETE'
  ].includes(effect.type);
}

export function isNetworkEffect(effect: BaseEffect): effect is NetworkEffect {
  return ['NET_CONNECT', 'NET_LISTEN'].includes(effect.type);
}

export function isProcessEffect(effect: BaseEffect): effect is ProcessEffect {
  return effect.type === 'PROCESS_SPAWN';
}

/**
 * Secret-scrubbing serialization helper for ObservedEffects.
 * Redacts values matching credential/token patterns from command lines or targets.
 */
export function serializeObservedEffects(effects: ObservedEffects): string {
  const secretKeyRegex = /(?:key|secret|token|password|api|auth|pwd|pass|credentials|credential|private|cert)\b.*?([a-zA-Z0-9_\-\.\=\+\/]{8,})/gi;

  const scrubString = (str: string): string => {
    return str.replace(secretKeyRegex, (match, p1) => {
      return match.replace(p1, '[REDACTED_SECRET]');
    });
  };

  const scrubbed = {
    filesystem: effects.filesystem.map(f => ({
      ...f,
      target: scrubString(f.target)
    })),
    network: effects.network.map(n => ({
      ...n,
      host: scrubString(n.host),
      target: scrubString(n.target)
    })),
    processes: effects.processes.map(p => ({
      ...p,
      commandLine: scrubString(p.commandLine),
      target: scrubString(p.target)
    }))
  };

  return JSON.stringify(scrubbed);
}
