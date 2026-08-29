import path from 'path';
import { ObservedEffects } from './effectTypes.js';

export interface ChangeImpact {
  readonly score: number;
  readonly severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  readonly filesChanged: number;
  readonly filesCreated: number;
  readonly filesDeleted: number;
  readonly criticalPathsTouched: number;
  readonly unexpectedEffects: number;
  readonly reasons: readonly string[];
}

export class ChangeImpactIntelligence {
  private readonly workspaceRoot: string;

  constructor(workspaceRoot: string) {
    this.workspaceRoot = path.resolve(workspaceRoot);
  }

  /**
   * Deterministically calculates change impact metrics from observed execution effects
   */
  calculate(observedEffects: ObservedEffects, totalWorkspaceFiles: number): ChangeImpact {
    let filesCreated = 0;
    let filesChanged = 0;
    let filesDeleted = 0;
    let criticalPathsTouched = 0;
    let unexpectedEffects = 0;
    const reasons: string[] = [];

    const criticalFiles = ['.env', 'package.json', 'tsconfig.json', '.gitignore', 'package-lock.json'];

    for (const fEffect of observedEffects.filesystem) {
      const canonicalTarget = path.resolve(fEffect.target);
      const basename = path.basename(canonicalTarget);

      // Check critical file modification
      if (criticalFiles.includes(basename) || canonicalTarget.includes(path.sep + '.git' + path.sep)) {
        criticalPathsTouched++;
        reasons.push(`Modified sensitive configuration file: ${basename}`);
      }

      // Unexpected effect classification: outside standard target build/coverage outputs
      const relativePath = path.relative(this.workspaceRoot, canonicalTarget);
      const isExpectedPath = 
        relativePath.startsWith('dist') || 
        relativePath.startsWith('build') || 
        relativePath.startsWith('coverage') || 
        relativePath.startsWith('tmp') ||
        relativePath.startsWith('.nyc_output');

      if (!isExpectedPath && fEffect.type !== 'FILE_READ') {
        unexpectedEffects++;
      }

      if (fEffect.type === 'FILE_CREATE') {
        filesCreated++;
      } else if (fEffect.type === 'FILE_WRITE') {
        filesChanged++;
      } else if (fEffect.type === 'FILE_DELETE') {
        filesDeleted++;
      }
    }

    // Blast-radius score calculations
    let score = (filesCreated * 10) + (filesChanged * 5) + (filesDeleted * 15) + (criticalPathsTouched * 50);

    if (totalWorkspaceFiles > 0) {
      const percentAffected = ((filesCreated + filesChanged + filesDeleted) / totalWorkspaceFiles) * 100;
      if (percentAffected > 25) {
        score += 30;
        reasons.push(`High workspace modification ratio: ${percentAffected.toFixed(1)}% of files affected`);
      }
    }

    if (unexpectedEffects > 0) {
      score += unexpectedEffects * 5;
      reasons.push(`Unexpected writes detected outside build/coverage output directories`);
    }

    let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (score > 100) {
      severity = 'CRITICAL';
    } else if (score > 50) {
      severity = 'HIGH';
    } else if (score > 15) {
      severity = 'MEDIUM';
    }

    if (reasons.length === 0) {
      reasons.push('No suspicious or high-severity changes detected');
    }

    return {
      score,
      severity,
      filesChanged,
      filesCreated,
      filesDeleted,
      criticalPathsTouched,
      unexpectedEffects,
      reasons
    };
  }
}
