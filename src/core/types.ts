/**
 * CodeGuardian Core Types and Contracts
 * Strongly typed discriminated unions and interfaces for the security pipeline.
 */

export type OperationType =
  | 'READ'
  | 'WRITE'
  | 'DELETE'
  | 'LIST'
  | 'EXECUTE'
  | 'UNKNOWN';

export type SensitivityTier =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW';

export type RiskLevel =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

export type BlastRadiusScope =
  | 'LOCAL'
  | 'MODULE'
  | 'WORKSPACE'
  | 'SYSTEM';

export type Reversibility =
  | 'REVERSIBLE'
  | 'IRREVERSIBLE';

export type PolicyDecisionType =
  | 'ALLOW'
  | 'ASK_USER'
  | 'BLOCK';

export type UserDecisionType =
  | 'ALLOW_ONCE'
  | 'ALLOW_SESSION'
  | 'DENY';

export type ExecutionStatus =
  | 'SUCCESS'
  | 'FAILURE'
  | 'BLOCKED'
  | 'DENIED';

export type VerificationStatus =
  | 'VERIFIED'
  | 'FAILED'
  | 'SKIPPED';

/**
 * An action proposed by an AI model or planner.
 * Treated as untrusted input until evaluated by the security pipeline.
 */
export interface ActionProposal {
  readonly actionId: string;
  readonly toolName: string;
  readonly operation: OperationType;
  readonly targetPath?: string;
  readonly parameters: Record<string, any>;
  readonly reason?: string;
  readonly sourceModel: string;
  readonly timestamp: number;
}

/**
 * Result of PathGuard evaluation
 */
export interface PathGuardResult {
  readonly allowed: boolean;
  readonly canonicalPath: string;
  readonly relativePath: string;
  readonly error?: string;
}

/**
 * Security analysis of the proposed target and action scope
 */
export interface SecurityEvaluation {
  readonly isWorkspaceContained: boolean;
  readonly canonicalPath?: string;
  readonly relativePath?: string;
  readonly sensitivity: SensitivityTier;
  readonly blastRadius: BlastRadiusScope;
  readonly reversibility: Reversibility;
  readonly violations: readonly string[];
}

/**
 * Deterministic risk assessment calculated independently of the LLM
 */
export interface RiskAssessment {
  readonly level: RiskLevel;
  readonly score: number;
  readonly factors: readonly string[];
}

/**
 * Outcome of policy evaluation
 */
export interface PolicyDecision {
  readonly decision: PolicyDecisionType;
  readonly matchedRule: string;
  readonly reason: string;
  readonly requiresUserConfirmation: boolean;
}

/**
 * Diff summary generated for user confirmation
 */
export interface DiffSummary {
  readonly filePath: string;
  readonly linesAdded: number;
  readonly linesRemoved: number;
  readonly diffText: string;
}

/**
 * User permission prompt request payload
 */
export interface PermissionRequest {
  readonly action: ActionProposal;
  readonly security: SecurityEvaluation;
  readonly risk: RiskAssessment;
  readonly policy: PolicyDecision;
  readonly diff?: DiffSummary;
}

/**
 * Result of tool execution
 */
export interface ToolResult {
  readonly success: boolean;
  readonly data?: any;
  readonly error?: string;
  readonly executionTimeMs: number;
}

/**
 * Pre-modification snapshot for atomic rollback
 */
export interface ChangeSnapshot {
  readonly snapshotId: string;
  readonly filePath: string;
  readonly originalContent: string | null;
  readonly originalHash: string | null;
  readonly timestamp: number;
}

/**
 * Tamper-evident, structured audit record
 */
export interface AuditRecord {
  readonly eventId: string;
  readonly timestamp: number;
  readonly actionId: string;
  readonly sourceModel: string;
  readonly operation: OperationType;
  readonly target: string;
  readonly risk: RiskLevel;
  readonly policyDecision: PolicyDecisionType;
  readonly matchedRule: string;
  readonly userDecision?: UserDecisionType;
  readonly executionResult: ExecutionStatus;
  readonly beforeHash?: string | null;
  readonly afterHash?: string | null;
  readonly errorReason?: string;
  readonly verificationStatus?: VerificationStatus;
}

/**
 * A proposed process execution command
 */
export interface CommandProposal {
  readonly command: string;
  readonly workingDirectory: string;
  readonly purpose: 'TEST' | 'LINT' | 'BUILD' | 'TYPECHECK' | 'OTHER';
  readonly requestedBy: 'AGENT' | 'USER' | 'SYSTEM';
}

/**
 * Policy outcome decision for command execution
 */
export type CommandDecision = 'ALLOW' | 'ASK_USER' | 'BLOCK';

/**
 * Structured outcome of a child process execution
 */
export interface ProcessResult {
  readonly command: string;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly durationMs: number;
  readonly decision: CommandDecision;
}

/**
 * Resolved executable metadata
 */
export interface ResolvedExecutable {
  readonly requestedName: string;
  readonly resolvedPath: string;
  readonly trusted: boolean;
  readonly source: 'SYSTEM' | 'WORKSPACE' | 'UNKNOWN';
}

/**
 * Bounded Capability Grant generated for process execution
 */
export interface CapabilityGrant {
  readonly id: string;
  readonly operation: OperationType;
  readonly workspaceRoot: string;
  readonly allowedPaths: readonly string[];
  readonly deniedPaths: readonly string[];
  readonly network: 'NONE' | 'LIMITED' | 'FULL';
  readonly processExecution: boolean;
  readonly maxExecutionTimeMs: number;
  readonly maxOutputBytes: number;
  readonly grantedAt: number;
  readonly expiresAt: number;
}

/**
 * Active process execution context
 */
export interface ProcessExecutionContext {
  readonly pid?: number;
  readonly processGroupId?: number;
  readonly startedAt: number;
  readonly workspaceRoot: string;
  readonly command: string;
  readonly descendants: Set<number>;
}

