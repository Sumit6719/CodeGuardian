import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export const GENESIS_PREVIOUS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export interface EvidenceRecordData {
  actionId: string;
  operation: string;
  target: string;
  provider: string;
  model?: string;
  risk: {
    level: string;
    score: number;
  };
  decision: string;
  matchedRule?: string;
  userDecision?: string;
  originalSha256?: string;
  proposedSha256?: string;
  finalSha256?: string;
  diffSummary?: {
    additions: number;
    deletions: number;
    changedLines: number;
  };
  syntax?: string;
  execution: string;
  verification: string;
  rollback?: {
    attempted: boolean;
    verified: boolean;
    error?: string;
  };
  command?: string;
  exitCode?: number | null;
  signal?: string | null;
  durationMs?: number;
  stdoutHash?: string;
  stderrHash?: string;
  timedOut?: boolean;
  details?: Record<string, any>;
}

export interface EvidenceRecord {
  recordId: string;
  timestamp: string;
  event: string;
  previousRecordHash: string;
  data: EvidenceRecordData;
  currentRecordHash: string;
}

export interface LedgerIntegrityResult {
  valid: boolean;
  totalRecords: number;
  error?: string;
  violatedRecordId?: string;
  violatedRecordIndex?: number;
}

export class EvidenceLedger {
  private readonly ledgerFilePath: string;

  constructor(ledgerFilePath: string) {
    this.ledgerFilePath = ledgerFilePath;
    const parentDir = path.dirname(this.ledgerFilePath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }
  }

  getLedgerFilePath(): string {
    return this.ledgerFilePath;
  }

  /**
   * Deterministically sorts object keys for canonical serialization
   */
  private canonicalJson(obj: any): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return `[${obj.map(item => this.canonicalJson(item)).join(',')}]`;
    }
    const sortedKeys = Object.keys(obj)
      .filter(k => obj[k] !== undefined)
      .sort();
    const parts = sortedKeys.map(k => `${JSON.stringify(k)}:${this.canonicalJson(obj[k])}`);
    return `{${parts.join(',')}}`;
  }

  /**
   * Computes the cryptographic SHA-256 hash for a record
   */
  computeRecordHash(previousHash: string, recordId: string, timestamp: string, event: string, data: EvidenceRecordData): string {
    const payload = `${previousHash}:${recordId}:${timestamp}:${event}:${this.canonicalJson(data)}`;
    return crypto.createHash('sha256').update(payload, 'utf-8').digest('hex');
  }

  /**
   * Reads all evidence records from the ledger file
   */
  readAll(): EvidenceRecord[] {
    if (!fs.existsSync(this.ledgerFilePath)) {
      return [];
    }

    try {
      const content = fs.readFileSync(this.ledgerFilePath, 'utf-8');
      return content
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.length > 0)
        .map(l => JSON.parse(l) as EvidenceRecord);
    } catch (err) {
      console.error('[EvidenceLedger] Error reading records:', err);
      return [];
    }
  }

  /**
   * Appends an evidence record linked to the previous record hash in a tamper-evident chain
   */
  record(event: string, data: EvidenceRecordData): EvidenceRecord {
    const records = this.readAll();
    const previousRecordHash = records.length > 0
      ? records[records.length - 1].currentRecordHash
      : GENESIS_PREVIOUS_HASH;

    const timestamp = new Date().toISOString();
    const recordId = `rec_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const currentRecordHash = this.computeRecordHash(previousRecordHash, recordId, timestamp, event, data);

    const record: EvidenceRecord = {
      recordId,
      timestamp,
      event,
      previousRecordHash,
      data,
      currentRecordHash
    };

    const line = JSON.stringify(record) + '\n';
    fs.appendFileSync(this.ledgerFilePath, line, 'utf-8');

    return record;
  }

  /**
   * Verifies the cryptographic integrity of the entire hash chain
   */
  verifyLedgerIntegrity(): LedgerIntegrityResult {
    const records = this.readAll();

    if (records.length === 0) {
      return {
        valid: true,
        totalRecords: 0
      };
    }

    for (let i = 0; i < records.length; i++) {
      const r = records[i];

      // 1. Chain continuity verification
      const expectedPrev = i === 0 ? GENESIS_PREVIOUS_HASH : records[i - 1].currentRecordHash;
      if (r.previousRecordHash !== expectedPrev) {
        return {
          valid: false,
          totalRecords: records.length,
          violatedRecordId: r.recordId,
          violatedRecordIndex: i,
          error: `Broken chain link at index ${i} (${r.recordId}). Expected previous hash ${expectedPrev}, found ${r.previousRecordHash}`
        };
      }

      // 2. Hash integrity verification
      const recomputedHash = this.computeRecordHash(
        r.previousRecordHash,
        r.recordId,
        r.timestamp,
        r.event,
        r.data
      );

      if (recomputedHash !== r.currentRecordHash) {
        return {
          valid: false,
          totalRecords: records.length,
          violatedRecordId: r.recordId,
          violatedRecordIndex: i,
          error: `Tampered record detected at index ${i} (${r.recordId}). Recomputed hash ${recomputedHash} does not match stored hash ${r.currentRecordHash}`
        };
      }
    }

    return {
      valid: true,
      totalRecords: records.length
    };
  }
}
