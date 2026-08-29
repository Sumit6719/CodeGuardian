import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ChangeSnapshot } from '../core/types.js';

export class SnapshotManager {
  private readonly snapshotDir: string;
  private readonly snapshots = new Map<string, ChangeSnapshot>();

  constructor(snapshotDir: string) {
    this.snapshotDir = snapshotDir;
    if (!fs.existsSync(this.snapshotDir)) {
      fs.mkdirSync(this.snapshotDir, { recursive: true });
    }
  }

  /**
   * Computes SHA-256 hash of a string
   */
  computeHash(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
  }

  /**
   * Creates and persists a pre-modification snapshot
   */
  createSnapshot(filePath: string): ChangeSnapshot {
    const timestamp = Date.now();
    const snapshotId = `snap_${timestamp}_${Math.random().toString(36).slice(2, 8)}`;

    let originalContent: string | null = null;
    let originalHash: string | null = null;

    if (fs.existsSync(filePath)) {
      originalContent = fs.readFileSync(filePath, 'utf-8');
      originalHash = this.computeHash(originalContent);

      // Persist snapshot file to disk
      const backupPath = path.join(this.snapshotDir, `${snapshotId}.bak`);
      fs.writeFileSync(backupPath, originalContent, 'utf-8');
    }

    const snapshot: ChangeSnapshot = {
      snapshotId,
      filePath,
      originalContent,
      originalHash,
      timestamp
    };

    this.snapshots.set(snapshotId, snapshot);
    return snapshot;
  }

  /**
   * Restores a file to its state recorded in the snapshot
   */
  restore(snapshotId: string): boolean {
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) {
      return false;
    }

    try {
      if (snapshot.originalContent === null) {
        // File did not exist before, remove created file
        if (fs.existsSync(snapshot.filePath)) {
          fs.unlinkSync(snapshot.filePath);
        }
      } else {
        // Restore original content
        fs.writeFileSync(snapshot.filePath, snapshot.originalContent, 'utf-8');
      }
      return true;
    } catch (err) {
      console.error(`[SnapshotManager] Failed to restore snapshot ${snapshotId}:`, err);
      return false;
    }
  }

  getSnapshot(snapshotId: string): ChangeSnapshot | undefined {
    return this.snapshots.get(snapshotId);
  }
}
