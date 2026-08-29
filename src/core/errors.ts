/**
 * CodeGuardian Domain Errors
 * Structured errors for security violations, path traversal, and policy blocks.
 */

export class CodeGuardianError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'CodeGuardianError';
  }
}

export class SecurityViolationError extends CodeGuardianError {
  constructor(message: string, public readonly violations: readonly string[]) {
    super(message, 'SECURITY_VIOLATION');
    this.name = 'SecurityViolationError';
  }
}

export class PathTraversalError extends CodeGuardianError {
  constructor(
    message: string,
    public readonly requestedPath: string,
    public readonly workspaceRoot: string
  ) {
    super(message, 'PATH_TRAVERSAL_DETECTED');
    this.name = 'PathTraversalError';
  }
}

export class PolicyBlockedError extends CodeGuardianError {
  constructor(
    message: string,
    public readonly matchedRule: string,
    public readonly operation: string,
    public readonly target: string
  ) {
    super(message, 'POLICY_BLOCKED');
    this.name = 'PolicyBlockedError';
  }
}

export class UserDeniedError extends CodeGuardianError {
  constructor(message: string, public readonly actionId: string) {
    super(message, 'USER_DENIED_ACTION');
    this.name = 'UserDeniedError';
  }
}

export class AtomicWriteError extends CodeGuardianError {
  constructor(message: string, public readonly targetPath: string, public readonly originalError?: Error) {
    super(message, 'ATOMIC_WRITE_FAILED');
    this.name = 'AtomicWriteError';
  }
}

export class VerificationError extends CodeGuardianError {
  constructor(message: string, public readonly targetPath: string) {
    super(message, 'VERIFICATION_FAILED');
    this.name = 'VerificationError';
  }
}
