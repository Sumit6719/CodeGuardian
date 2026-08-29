import {
  OperationType,
  SensitivityTier,
  BlastRadiusScope,
  RiskAssessment,
  PolicyDecisionType
} from '../core/types.js';

export interface PolicyContext {
  operation: OperationType;
  targetPath: string;
  relativePath: string;
  isWorkspaceContained: boolean;
  sensitivity: SensitivityTier;
  blastRadius: BlastRadiusScope;
  risk: RiskAssessment;
}

export interface PolicyEvaluationResult {
  applicable: boolean;
  decision?: PolicyDecisionType;
  reason?: string;
  ruleId?: string;
}

export interface IPolicyRule {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  evaluate(context: PolicyContext): PolicyEvaluationResult;
}
