import crypto from 'crypto';
import { CapabilityGrant, OperationType } from '../../core/types.js';

export class CapabilityManager {
  private readonly workspaceRoot: string;

  constructor(workspaceRoot: string) {
    this.workspaceRoot = workspaceRoot;
  }

  /**
   * Creates a capability grant for the proposed command execution.
   */
  generateGrant(
    operation: OperationType,
    policyDecision: 'ALLOW' | 'ASK_USER' | 'BLOCK',
    customOptions?: {
      maxExecutionTimeMs?: number;
      maxOutputBytes?: number;
      allowedPaths?: string[];
      deniedPaths?: string[];
    }
  ): CapabilityGrant {
    const id = `cap_${crypto.randomUUID()}`;
    const grantedAt = Date.now();
    const expiresAt = grantedAt + (5 * 60 * 1000); // 5 mins default duration

    // Safe defaults:
    // If blocked by policy, processExecution is false.
    const processExecution = policyDecision !== 'BLOCK';

    return {
      id,
      operation,
      workspaceRoot: this.workspaceRoot,
      allowedPaths: customOptions?.allowedPaths || [this.workspaceRoot],
      deniedPaths: customOptions?.deniedPaths || [],
      network: 'NONE', // No network permission allowed by default
      processExecution,
      maxExecutionTimeMs: customOptions?.maxExecutionTimeMs ?? 60000, // 60s default
      maxOutputBytes: customOptions?.maxOutputBytes ?? 100 * 1024, // 100KB default
      grantedAt,
      expiresAt
    };
  }

  /**
   * Checks if a capability grant is still valid (not expired, fits workspace, correct action).
   */
  validateGrant(grant: CapabilityGrant, requestedDir: string, requestedOp: OperationType): { valid: boolean; reason?: string } {
    if (Date.now() > grant.expiresAt) {
      return { valid: false, reason: 'Capability grant has expired.' };
    }
    if (grant.workspaceRoot.replace(/\\/g, '/').toLowerCase() !== this.workspaceRoot.replace(/\\/g, '/').toLowerCase()) {
      return { valid: false, reason: 'Capability grant workspace root mismatch.' };
    }
    if (grant.operation !== requestedOp) {
      return { valid: false, reason: `Capability grant operation mismatch: expected ${grant.operation}, got ${requestedOp}.` };
    }
    if (!grant.processExecution && requestedOp === 'EXECUTE') {
      return { valid: false, reason: 'Capability grant does not permit process execution.' };
    }

    // Check if target directory is within allowed paths and not denied
    const normalizedReqDir = requestedDir.replace(/\\/g, '/').toLowerCase();
    
    const isAllowed = grant.allowedPaths.some(p => {
      const normAllowed = p.replace(/\\/g, '/').toLowerCase();
      return normalizedReqDir.startsWith(normAllowed);
    });

    if (!isAllowed) {
      return { valid: false, reason: `Path "${requestedDir}" is not in the allowed paths list of this capability.` };
    }

    const isDenied = grant.deniedPaths.some(p => {
      const normDenied = p.replace(/\\/g, '/').toLowerCase();
      return normalizedReqDir.startsWith(normDenied);
    });

    if (isDenied) {
      return { valid: false, reason: `Path "${requestedDir}" is explicitly denied in this capability.` };
    }

    return { valid: true };
  }
}
