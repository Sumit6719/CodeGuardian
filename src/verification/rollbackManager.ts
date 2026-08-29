import fs from 'fs';
import crypto from 'crypto';
import { ChangeSnapshot } from '../core/types.js';
import { SnapshotManager } from './snapshotManager.js';

export interface RollbackResult {
  readonly success: boolean;
  readonly verified: boolean;
  readonly filePath: string;
  readonly originalHash: string | null;
  readonly restoredHash: string | null;
  readonly error?: string;
}

export class RollbackManager {
  private readonly snapshotManager: SnapshotManager;

  constructor(snapshotManager: SnapshotManager) {
    this.snapshotManager = snapshotManager;
  }

  /**
   * Computes SHA-256 of content
   */
  private computeHash(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
  }

  /**
   * Restores a file to its exact snapshot state and independently verifies the restored state.
   */
  rollback(snapshotOrId: ChangeSnapshot | string): RollbackResult {
    const snapshot = typeof snapshotOrId === 'string'
      ? this.snapshotManager.getSnapshot(snapshotOrId)
      : snapshotOrId;

    if (!snapshot) {
      return {
        success: false,
        verified: false,
        filePath: '',
        originalHash: null,
        restoredHash: null,
        error: `Snapshot not found: ${snapshotOrId}`
      };
    }

    const { filePath, originalContent, originalHash } = snapshot;

    try {
      if (originalContent === null) {
        // Case 1: File did not exist before AI modification (new file creation)
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }

        // Post-rollback verification for new file deletion
        const existsAfter = fs.existsSync(filePath);
        if (existsAfter) {
          return {
            success: false,
            verified: false,
            filePath,
            originalHash: null,
            restoredHash: null,
            error: `Rollback verification failed: newly created file ${filePath} could not be removed.`
          };
        }

        return {
          success: true,
          verified: true,
          filePath,
          originalHash: null,
          restoredHash: null
        };
      } else {
        // Case 2: File existed before AI modification (file update)
        fs.writeFileSync(filePath, originalContent, 'utf-8');

        // Post-rollback verification for restored content
        if (!fs.existsSync(filePath)) {
          return {
            success: false,
            verified: false,
            filePath,
            originalHash,
            restoredHash: null,
            error: `Rollback verification failed: restored file does not exist at ${filePath}.`
          };
        }

        const restoredContent = fs.readFileSync(filePath, 'utf-8');
        const restoredHash = this.computeHash(restoredContent);

        if (restoredHash !== originalHash) {
          return {
            success: false,
            verified: false,
            filePath,
            originalHash,
            restoredHash,
            error: `Rollback verification failed: restored file hash (${restoredHash}) does not match original snapshot hash (${originalHash}).`
          };
        }

        return {
          success: true,
          verified: true,
          filePath,
          originalHash,
          restoredHash
        };
      }
    } catch (err: any) {
      return {
        success: false,
        verified: false,
        filePath,
        originalHash,
        restoredHash: null,
        error: `Rollback exception: ${err.message}`
      };
    }
  }
}
