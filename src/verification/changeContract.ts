import {
  OperationType,
  RiskLevel,
  PolicyDecisionType,
  UserDecisionType
} from '../core/types.js';
import { FileDiff } from './diffEngine.js';

export type VerificationStatusType = 'PASS' | 'FAIL' | 'SKIPPED';

export type ContractStage =
  | 'PROPOSED'
  | 'VERIFIED_PRE_APPLY'
  | 'USER_APPROVED'
  | 'APPLIED'
  | 'REJECTED_SECURITY'
  | 'REJECTED_SYNTAX'
  | 'REJECTED_USER'
  | 'ROLLED_BACK';

export interface ChangeContract {
  readonly actionId: string;
  readonly operation: OperationType;
  readonly targetPath: string;
  readonly canonicalPath?: string;

  readonly requestedBy: {
    readonly provider: string;
    readonly model?: string;
  };

  readonly risk: {
    readonly level: RiskLevel;
    readonly score: number;
    readonly factors?: readonly string[];
  };

  readonly permission: {
    readonly decision: PolicyDecisionType;
    readonly policyRule?: string;
    readonly reason?: string;
    readonly userDecision?: UserDecisionType;
  };

  readonly before: {
    readonly exists: boolean;
    readonly sha256?: string;
    readonly lineCount?: number;
  };

  readonly after: {
    readonly exists: boolean;
    readonly sha256?: string;
    readonly lineCount?: number;
  };

  readonly diff?: FileDiff;

  readonly verification?: {
    readonly syntax: VerificationStatusType;
    readonly integrity: VerificationStatusType;
    readonly errors: readonly string[];
  };

  readonly stage: ContractStage;
  readonly timestamp: string;
}

export function createChangeContract(params: {
  actionId: string;
  operation: OperationType;
  targetPath: string;
  canonicalPath?: string;
  provider: string;
  model?: string;
  riskLevel: RiskLevel;
  riskScore: number;
  riskFactors?: readonly string[];
  policyDecision: PolicyDecisionType;
  policyRule?: string;
  policyReason?: string;
  userDecision?: UserDecisionType;
  beforeExists: boolean;
  beforeSha256?: string;
  beforeLineCount?: number;
  afterExists: boolean;
  afterSha256?: string;
  afterLineCount?: number;
  diff?: FileDiff;
  syntaxStatus?: VerificationStatusType;
  integrityStatus?: VerificationStatusType;
  verificationErrors?: readonly string[];
  stage?: ContractStage;
}): ChangeContract {
  return {
    actionId: params.actionId,
    operation: params.operation,
    targetPath: params.targetPath,
    canonicalPath: params.canonicalPath,
    requestedBy: {
      provider: params.provider,
      model: params.model
    },
    risk: {
      level: params.riskLevel,
      score: params.riskScore,
      factors: params.riskFactors
    },
    permission: {
      decision: params.policyDecision,
      policyRule: params.policyRule,
      reason: params.policyReason,
      userDecision: params.userDecision
    },
    before: {
      exists: params.beforeExists,
      sha256: params.beforeSha256,
      lineCount: params.beforeLineCount
    },
    after: {
      exists: params.afterExists,
      sha256: params.afterSha256,
      lineCount: params.afterLineCount
    },
    diff: params.diff,
    verification: {
      syntax: params.syntaxStatus || 'SKIPPED',
      integrity: params.integrityStatus || 'SKIPPED',
      errors: params.verificationErrors || []
    },
    stage: params.stage || 'PROPOSED',
    timestamp: new Date().toISOString()
  };
}
