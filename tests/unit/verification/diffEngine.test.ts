import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DiffEngine } from '../../../src/verification/diffEngine.js';

describe('DiffEngine & Hash Verification', () => {
  const engine = new DiffEngine(50);

  it('computes consistent SHA-256 hashes (same content -> same hash)', () => {
    const hash1 = engine.computeHash('function hello() { return "world"; }');
    const hash2 = engine.computeHash('function hello() { return "world"; }');
    assert.equal(hash1, hash2);
    assert.match(hash1, /^[a-f0-9]{64}$/);
  });

  it('computes distinct SHA-256 hashes for different contents', () => {
    const hash1 = engine.computeHash('content A');
    const hash2 = engine.computeHash('content B');
    assert.notEqual(hash1, hash2);
  });

  it('handles newly created files (originalContent is null)', () => {
    const proposed = 'console.log("new file");\n';
    const diff = engine.generateDiff('src/new.js', null, proposed);

    assert.equal(diff.filePath, 'src/new.js');
    assert.equal(diff.originalHash, '');
    assert.match(diff.proposedHash, /^[a-f0-9]{64}$/);
    assert.equal(diff.additions, 1);
    assert.equal(diff.deletions, 0);
    assert.equal(diff.changedLines, 1);
    assert.ok(diff.unifiedDiff.includes('+console.log("new file");'));
  });

  it('handles modified existing files accurately', () => {
    const original = 'const a = 1;\nconst b = 2;\n';
    const proposed = 'const a = 1;\nconst b = 3;\nconst c = 4;\n';

    const diff = engine.generateDiff('src/app.js', original, proposed);

    assert.equal(diff.filePath, 'src/app.js');
    assert.equal(diff.deletions, 1); // const b = 2;
    assert.equal(diff.additions, 2); // const b = 3; const c = 4;
    assert.equal(diff.changedLines, 3);
    assert.notEqual(diff.originalHash, diff.proposedHash);
    assert.ok(diff.unifiedDiff.includes('-const b = 2;'));
    assert.ok(diff.unifiedDiff.includes('+const b = 3;'));
  });

  it('handles completely deleted or cleared files', () => {
    const original = 'line 1\nline 2\nline 3\n';
    const proposed = '';

    const diff = engine.generateDiff('src/clear.js', original, proposed);

    assert.equal(diff.additions, 0);
    assert.equal(diff.deletions, 3);
    assert.equal(diff.changedLines, 3);
  });

  it('handles identical/unchanged files with zero metrics and empty diff', () => {
    const content = 'const unchanged = true;\n';
    const diff = engine.generateDiff('src/same.js', content, content);

    assert.equal(diff.additions, 0);
    assert.equal(diff.deletions, 0);
    assert.equal(diff.changedLines, 0);
    assert.equal(diff.originalHash, diff.proposedHash);
    assert.equal(diff.unifiedDiff, '');
  });

  it('handles empty original and empty proposed files', () => {
    const diff = engine.generateDiff('src/empty.js', '', '');
    assert.equal(diff.additions, 0);
    assert.equal(diff.deletions, 0);
    assert.equal(diff.changedLines, 0);
    assert.equal(diff.unifiedDiff, '');
  });

  it('handles Unicode and multi-byte characters accurately', () => {
    const original = '// Unicode: 🚀 Hello\n';
    const proposed = '// Unicode: 🛡️ CodeGuardian 安全\n';

    const diff = engine.generateDiff('src/unicode.js', original, proposed);

    assert.equal(diff.additions, 1);
    assert.equal(diff.deletions, 1);
    assert.ok(diff.unifiedDiff.includes('🛡️ CodeGuardian 安全'));
  });

  it('safely handles large file diffs by truncating display lines while preserving exact counts', () => {
    const smallEngine = new DiffEngine(10); // truncate at 10 display lines

    let original = '';
    let proposed = '';
    for (let i = 0; i < 50; i++) {
      original += `line ${i}\n`;
      proposed += `modified line ${i}\n`;
    }

    const diff = smallEngine.generateDiff('src/large.js', original, proposed);

    assert.equal(diff.additions, 50);
    assert.equal(diff.deletions, 50);
    assert.equal(diff.changedLines, 100);
    assert.ok(diff.unifiedDiff.includes('truncated for display'));
  });
});
