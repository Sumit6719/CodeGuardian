import fs from 'fs';
import path from 'path';
import { AuditRecord } from '../core/types.js';

export class AuditLogger {
  private readonly logFilePath: string;

  constructor(logFilePath: string) {
    this.logFilePath = logFilePath;
    const parentDir = path.dirname(this.logFilePath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }
  }

  getLogFilePath(): string {
    return this.logFilePath;
  }

  /**
   * Appends an audit record to the append-only JSONL log file.
   */
  log(record: AuditRecord): void {
    try {
      const line = JSON.stringify(record) + '\n';
      // Append mode guarantees records are never overwritten
      fs.appendFileSync(this.logFilePath, line, 'utf-8');
    } catch (err) {
      console.error('[AuditLogger] Failed to write audit record:', err);
    }
  }

  /**
   * Reads all audit records from disk (for auditing and verification)
   */
  readAll(): AuditRecord[] {
    if (!fs.existsSync(this.logFilePath)) {
      return [];
    }

    try {
      const content = fs.readFileSync(this.logFilePath, 'utf-8');
      return content
        .split('\n')
        .filter(line => line.trim().length > 0)
        .map(line => JSON.parse(line) as AuditRecord);
    } catch (err) {
      console.error('[AuditLogger] Failed to read audit log:', err);
      return [];
    }
  }
}
