import fs from 'fs';
import crypto from 'crypto';
import { ChangeSnapshot } from '../core/types.js';

export interface IntegrityVerificationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
  readonly actualHash?: string;
}

export class IntegrityVerifier {
  /**
   * Verifies that the file on disk matches the expected state and that snapshot is intact
   */
  verify(filePath: string, expectedContent: string, snapshot: ChangeSnapshot): IntegrityVerificationResult {
    const errors: string[] = [];

    // 1. File existence
    if (!fs.existsSync(filePath)) {
      errors.push(`Integrity Failure: Modified file does not exist at ${filePath}`);
      return { valid: false, errors };
    }

    // 2. Readability and content matching
    let actualContent = '';
    try {
      actualContent = fs.readFileSync(filePath, 'utf-8');
    } catch (err: any) {
      errors.push(`Integrity Failure: Unable to read file back from disk: ${err.message}`);
      return { valid: false, errors };
    }

    // 3. Hash matching
    const expectedHash = crypto.createHash('sha256').update(expectedContent, 'utf-8').digest('hex');
    const actualHash = crypto.createHash('sha256').update(actualContent, 'utf-8').digest('hex');

    if (actualHash !== expectedHash) {
      errors.push(`Integrity Failure: Content hash mismatch. Expected ${expectedHash}, got ${actualHash}`);
    }

    // 4. Snapshot preservation check
    if (!snapshot || !snapshot.snapshotId) {
      errors.push('Integrity Failure: Original pre-change snapshot was not properly recorded.');
    }

    return {
      valid: errors.length === 0,
      errors,
      actualHash
    };
  }
}
