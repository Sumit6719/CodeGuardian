import path from 'path';

export interface CodeGuardianConfig {
  workspaceRoot: string;
  auditLogPath: string;
  evidenceLogPath: string;
  snapshotDir: string;
  maxIterations: number;
  maxToolCalls: number;
  maxFileModifications: number;
  maxFileReadSizeBytes: number;
  allowSessionApprovals: boolean;
}

export function createDefaultConfig(workspaceRoot: string, overrides?: Partial<CodeGuardianConfig>): CodeGuardianConfig {
  const resolvedRoot = path.resolve(workspaceRoot);
  const dotFolder = path.join(resolvedRoot, '.codeguardian');

  return {
    workspaceRoot: resolvedRoot,
    auditLogPath: path.join(dotFolder, 'audit.jsonl'),
    evidenceLogPath: path.join(dotFolder, 'evidence.jsonl'),
    snapshotDir: path.join(dotFolder, 'snapshots'),
    maxIterations: 20,
    maxToolCalls: 50,
    maxFileModifications: 15,
    maxFileReadSizeBytes: 512 * 1024, // 512 KB
    allowSessionApprovals: true,
    ...overrides
  };
}
