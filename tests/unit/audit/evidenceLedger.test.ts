import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
  EvidenceLedger,
  GENESIS_PREVIOUS_HASH,
  EvidenceRecordData
} from '../../../src/audit/evidenceLedger.js';

describe('EvidenceLedger Tamper-Evident Chain & Audit Integrity', () => {
  let testWorkspace: string;
  let ledgerPath: string;
  let ledger: EvidenceLedger;

  before(() => {
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cg_evidence_test_'));
    ledgerPath = path.join(testWorkspace, 'evidence.jsonl');
    ledger = new EvidenceLedger(ledgerPath);
  });

  after(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('records initial entry with genesis previous hash and valid cryptographic signature', () => {
    const data: EvidenceRecordData = {
      actionId: 'act_001',
      operation: 'WRITE',
      target: 'src/main.ts',
      provider: 'gemini',
      risk: { level: 'MEDIUM', score: 45 },
      decision: 'ASK_USER',
      userDecision: 'ALLOW_ONCE',
      originalSha256: 'aaaa1111',
      proposedSha256: 'bbbb2222',
      syntax: 'PASS',
      execution: 'SUCCESS',
      verification: 'PASS'
    };

    const record = ledger.record('ACTION_VERIFIED', data);

    assert.equal(record.previousRecordHash, GENESIS_PREVIOUS_HASH);
    assert.match(record.currentRecordHash, /^[a-f0-9]{64}$/);

    const recomputed = ledger.computeRecordHash(
      record.previousRecordHash,
      record.recordId,
      record.timestamp,
      record.event,
      record.data
    );
    assert.equal(record.currentRecordHash, recomputed);
  });

  it('chains subsequent records by referencing the preceding record hash', () => {
    const data2: EvidenceRecordData = {
      actionId: 'act_002',
      operation: 'READ',
      target: 'package.json',
      provider: 'gemini',
      risk: { level: 'LOW', score: 15 },
      decision: 'ALLOW',
      execution: 'SUCCESS',
      verification: 'PASS'
    };

    const data3: EvidenceRecordData = {
      actionId: 'act_003',
      operation: 'WRITE',
      target: 'src/utils.ts',
      provider: 'gemini',
      risk: { level: 'HIGH', score: 65 },
      decision: 'ASK_USER',
      userDecision: 'ALLOW_ONCE',
      execution: 'SUCCESS',
      verification: 'PASS'
    };

    const rec2 = ledger.record('ACTION_VERIFIED', data2);
    const rec3 = ledger.record('ACTION_VERIFIED', data3);

    const all = ledger.readAll();
    assert.equal(all.length, 3);

    // Verify chain links
    assert.equal(all[1].previousRecordHash, all[0].currentRecordHash);
    assert.equal(all[2].previousRecordHash, all[1].currentRecordHash);

    // Verify ledger passes integrity check
    const check = ledger.verifyLedgerIntegrity();
    assert.equal(check.valid, true);
    assert.equal(check.totalRecords, 3);
  });

  it('detects tampering when an existing record content is altered', () => {
    const lines = fs.readFileSync(ledgerPath, 'utf-8').trim().split('\n');
    const records = lines.map(l => JSON.parse(l));

    // Tamper with record at index 1: change operation from READ to WRITE
    records[1].data.operation = 'WRITE';
    records[1].data.risk.level = 'CRITICAL';

    // Write tampered records back to disk
    fs.writeFileSync(ledgerPath, records.map(r => JSON.stringify(r)).join('\n') + '\n', 'utf-8');

    const check = ledger.verifyLedgerIntegrity();
    assert.equal(check.valid, false);
    assert.equal(check.violatedRecordIndex, 1);
    assert.match(check.error || '', /tampered record detected/i);
  });

  it('detects broken chain links when a record is deleted', () => {
    const lines = fs.readFileSync(ledgerPath, 'utf-8').trim().split('\n');
    const records = lines.map(l => JSON.parse(l));

    // Remove the middle record (index 1)
    records.splice(1, 1);
    fs.writeFileSync(ledgerPath, records.map(r => JSON.stringify(r)).join('\n') + '\n', 'utf-8');

    const check = ledger.verifyLedgerIntegrity();
    assert.equal(check.valid, false);
    assert.match(check.error || '', /broken chain link/i);
  });

  it('detects broken chain link if previousRecordHash is arbitrarily altered', () => {
    const lines = fs.readFileSync(ledgerPath, 'utf-8').trim().split('\n');
    const records = lines.map(l => JSON.parse(l));

    // Modify previousRecordHash of the first record
    records[0].previousRecordHash = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    fs.writeFileSync(ledgerPath, records.map(r => JSON.stringify(r)).join('\n') + '\n', 'utf-8');

    const check = ledger.verifyLedgerIntegrity();
    assert.equal(check.valid, false);
    assert.match(check.error || '', /broken chain link/i);
  });
});
