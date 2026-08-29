import { IPolicyRule, PolicyContext, PolicyEvaluationResult } from './policy.interface.js';

export const RuleWorkspaceBoundary: IPolicyRule = {
  id: 'SEC-001-WORKSPACE-BOUNDARY',
  name: 'Workspace Boundary Enforcement',
  description: 'Prohibits any operation resolving outside the workspace root.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    if (!ctx.isWorkspaceContained) {
      return {
        applicable: true,
        decision: 'BLOCK',
        reason: 'Target path escapes workspace boundaries. Operation strictly blocked.',
        ruleId: 'SEC-001-WORKSPACE-BOUNDARY'
      };
    }
    return { applicable: false };
  }
};

export const RuleUnknownOperation: IPolicyRule = {
  id: 'SEC-002-UNKNOWN-OPERATION',
  name: 'Unknown Operation Fail-Closed',
  description: 'Rejects unknown operations.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    if (ctx.operation === 'UNKNOWN') {
      return {
        applicable: true,
        decision: 'BLOCK',
        reason: 'Unknown or unrecognized operation type. Failed closed.',
        ruleId: 'SEC-002-UNKNOWN-OPERATION'
      };
    }
    return { applicable: false };
  }
};

export const RuleCriticalSensitiveWrite: IPolicyRule = {
  id: 'SEC-003-CRITICAL-WRITE-PROTECTION',
  name: 'Critical Asset Write Protection',
  description: 'Blocks write and delete operations targeting credentials, secrets, or .env files.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    if (ctx.sensitivity === 'CRITICAL' && (ctx.operation === 'WRITE' || ctx.operation === 'DELETE')) {
      return {
        applicable: true,
        decision: 'BLOCK',
        reason: `Target is classified as CRITICAL sensitivity (${ctx.relativePath}). Write/Delete blocked by default security policy.`,
        ruleId: 'SEC-003-CRITICAL-WRITE-PROTECTION'
      };
    }
    return { applicable: false };
  }
};

export const RuleCriticalSensitiveRead: IPolicyRule = {
  id: 'SEC-004-CRITICAL-READ-PROTECTION',
  name: 'Critical Asset Read Protection',
  description: 'Blocks reading private keys, credentials, and raw .env files into model context.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    if (ctx.sensitivity === 'CRITICAL' && ctx.operation === 'READ') {
      return {
        applicable: true,
        decision: 'BLOCK',
        reason: `Target is classified as CRITICAL sensitivity (${ctx.relativePath}). Reading secrets into LLM context is blocked by default policy.`,
        ruleId: 'SEC-004-CRITICAL-READ-PROTECTION'
      };
    }
    return { applicable: false };
  }
};

export const RuleGitProtection: IPolicyRule = {
  id: 'SEC-005-GIT-INTERNAL-PROTECTION',
  name: 'Git Internal Metadata Protection',
  description: 'Prevents direct write or delete operations on .git directory internals.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    const norm = ctx.relativePath.replace(/\\/g, '/');
    if (/(^|\/)\.git(\/|$)/i.test(norm) && (ctx.operation === 'WRITE' || ctx.operation === 'DELETE')) {
      return {
        applicable: true,
        decision: 'BLOCK',
        reason: 'Direct modification of internal Git repository state (.git) is blocked.',
        ruleId: 'SEC-005-GIT-INTERNAL-PROTECTION'
      };
    }
    return { applicable: false };
  }
};

export const RuleExecuteBlocked: IPolicyRule = {
  id: 'SEC-006-EXECUTE-DISABLED',
  name: 'Execution Disabled in v0.1',
  description: 'Blocks external process/shell execution in v0.1.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    if (ctx.operation === 'EXECUTE') {
      return {
        applicable: true,
        decision: 'BLOCK',
        reason: 'External process execution is disabled in CodeGuardian v0.1.',
        ruleId: 'SEC-006-EXECUTE-DISABLED'
      };
    }
    return { applicable: false };
  }
};

export const RuleSafeRead: IPolicyRule = {
  id: 'PERM-001-SAFE-READ',
  name: 'Safe Workspace Read & List',
  description: 'Allows reading and listing non-critical workspace files.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    if (
      (ctx.operation === 'READ' || ctx.operation === 'LIST') &&
      (ctx.sensitivity === 'LOW' || ctx.sensitivity === 'MEDIUM' || ctx.sensitivity === 'HIGH')
    ) {
      return {
        applicable: true,
        decision: 'ALLOW',
        reason: 'Safe read-only operation on permitted workspace asset.',
        ruleId: 'PERM-001-SAFE-READ'
      };
    }
    return { applicable: false };
  }
};

export const RuleDeleteConfirmation: IPolicyRule = {
  id: 'PERM-002-DELETE-REQUIRES-CONFIRMATION',
  name: 'File Deletion User Confirmation',
  description: 'Requires explicit user confirmation for deleting files.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    if (ctx.operation === 'DELETE') {
      return {
        applicable: true,
        decision: 'ASK_USER',
        reason: 'File deletion is destructive and requires user authorization.',
        ruleId: 'PERM-002-DELETE-REQUIRES-CONFIRMATION'
      };
    }
    return { applicable: false };
  }
};

export const RuleSourceWriteConfirmation: IPolicyRule = {
  id: 'PERM-003-WRITE-REQUIRES-CONFIRMATION',
  name: 'File Modification User Confirmation',
  description: 'Requires explicit user confirmation for modifying workspace files.',
  evaluate(ctx: PolicyContext): PolicyEvaluationResult {
    if (ctx.operation === 'WRITE') {
      return {
        applicable: true,
        decision: 'ASK_USER',
        reason: 'File modification changes code on disk and requires user authorization.',
        ruleId: 'PERM-003-WRITE-REQUIRES-CONFIRMATION'
      };
    }
    return { applicable: false };
  }
};

export const RuleFailClosedFallback: IPolicyRule = {
  id: 'SEC-999-FAIL-CLOSED-FALLBACK',
  name: 'Fail-Closed Default Rule',
  description: 'Blocks any action not explicitly allowed by preceding rules.',
  evaluate(_ctx: PolicyContext): PolicyEvaluationResult {
    return {
      applicable: true,
      decision: 'BLOCK',
      reason: 'No policy rule explicitly permitted this operation. Failing closed.',
      ruleId: 'SEC-999-FAIL-CLOSED-FALLBACK'
    };
  }
};

export const DEFAULT_POLICY_RULES: readonly IPolicyRule[] = [
  RuleWorkspaceBoundary,
  RuleUnknownOperation,
  RuleCriticalSensitiveWrite,
  RuleCriticalSensitiveRead,
  RuleGitProtection,
  RuleExecuteBlocked,
  RuleSafeRead,
  RuleDeleteConfirmation,
  RuleSourceWriteConfirmation,
  RuleFailClosedFallback
];
