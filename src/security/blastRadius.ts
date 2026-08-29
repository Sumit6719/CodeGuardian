import { BlastRadiusScope, OperationType, SensitivityTier } from '../core/types.js';

export class BlastRadiusEstimator {
  estimate(
    operation: OperationType,
    relativePath: string,
    sensitivity: SensitivityTier,
    isContained: boolean
  ): BlastRadiusScope {
    if (!isContained) {
      return 'SYSTEM';
    }

    if (operation === 'EXECUTE') {
      return 'SYSTEM';
    }

    const norm = relativePath.replace(/\\/g, '/');

    // Root-level project configurations affect the entire workspace
    if (
      sensitivity === 'HIGH' &&
      !norm.includes('/') &&
      /(package\.json|tsconfig.*\.json|\.gitignore)$/i.test(norm)
    ) {
      return 'WORKSPACE';
    }

    // Operations on directory root
    if (norm === '' || norm === '.') {
      return 'WORKSPACE';
    }

    // If target is in a high-impact directory like .github or .git
    if (/^(\.github|\.git)(\/|$)/i.test(norm)) {
      return 'WORKSPACE';
    }

    // Default file modification is LOCAL to the module/file
    return 'LOCAL';
  }
}
