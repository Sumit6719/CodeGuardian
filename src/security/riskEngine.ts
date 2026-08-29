import {
  OperationType,
  SensitivityTier,
  BlastRadiusScope,
  RiskLevel,
  RiskAssessment
} from '../core/types.js';

export interface RiskEvaluationInput {
  operation: OperationType;
  sensitivity: SensitivityTier;
  blastRadius: BlastRadiusScope;
  isWorkspaceContained: boolean;
  targetPath: string;
}

export class RiskEngine {
  /**
   * Independently and deterministically calculates the risk level of an action.
   */
  evaluate(input: RiskEvaluationInput): RiskAssessment {
    const factors: string[] = [];

    // Invariant 1: Path outside workspace is always CRITICAL risk
    if (!input.isWorkspaceContained) {
      factors.push('Security Violation: Target path is outside workspace boundaries.');
      return {
        level: 'CRITICAL',
        score: 100,
        factors
      };
    }

    // Invariant 2: Write or Delete on CRITICAL sensitivity is always CRITICAL risk
    if (input.sensitivity === 'CRITICAL' && (input.operation === 'WRITE' || input.operation === 'DELETE')) {
      factors.push(`Destructive operation (${input.operation}) on CRITICAL asset (${input.targetPath}).`);
      return {
        level: 'CRITICAL',
        score: 95,
        factors
      };
    }

    let score = 0;

    // 1. Operation Factor
    switch (input.operation) {
      case 'LIST':
        score += 5;
        factors.push('Operation is read-only directory enumeration.');
        break;
      case 'READ':
        score += 10;
        factors.push('Operation is read-only file inspection.');
        break;
      case 'WRITE':
        score += 30;
        factors.push('Operation modifies file contents on disk.');
        break;
      case 'DELETE':
        score += 45;
        factors.push('Operation is destructive file deletion.');
        break;
      case 'EXECUTE':
        score += 70;
        factors.push('Operation invokes external process execution.');
        break;
      case 'UNKNOWN':
      default:
        score += 85;
        factors.push('Unknown or unrecognized operation type.');
        break;
    }

    // 2. Sensitivity Factor
    switch (input.sensitivity) {
      case 'LOW':
        score += 5;
        factors.push('Target sensitivity: LOW (documentation/temporary file).');
        break;
      case 'MEDIUM':
        score += 15;
        factors.push('Target sensitivity: MEDIUM (source code or asset).');
        break;
      case 'HIGH':
        score += 25;
        factors.push('Target sensitivity: HIGH (core config or build pipeline).');
        break;
      case 'CRITICAL':
        score += 50;
        factors.push('Target sensitivity: CRITICAL (credentials/secrets).');
        break;
    }

    // 3. Blast Radius Factor
    switch (input.blastRadius) {
      case 'LOCAL':
        score += 5;
        factors.push('Blast radius: LOCAL (single leaf file).');
        break;
      case 'MODULE':
        score += 15;
        factors.push('Blast radius: MODULE (multiple files or directory).');
        break;
      case 'WORKSPACE':
        score += 20;
        factors.push('Blast radius: WORKSPACE (root configuration or project-wide).');
        break;
      case 'SYSTEM':
        score += 35;
        factors.push('Blast radius: SYSTEM (unbounded external impact).');
        break;
    }

    // Determine final RiskLevel
    let level: RiskLevel;
    if (score >= 85) {
      level = 'CRITICAL';
    } else if (score >= 60) {
      level = 'HIGH';
    } else if (score >= 30) {
      level = 'MEDIUM';
    } else {
      level = 'LOW';
    }

    return {
      level,
      score,
      factors
    };
  }
}
