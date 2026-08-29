import { DiffSummary } from '../core/types.js';
import { DiffEngine } from './diffEngine.js';

export class DiffGenerator {
  private readonly engine = new DiffEngine(50);

  /**
   * Generates a unified diff and summary statistics (+lines, -lines)
   */
  generate(filePath: string, originalContent: string | null, newContent: string): DiffSummary {
    const diff = this.engine.generateDiff(filePath, originalContent, newContent);
    return {
      filePath: diff.filePath,
      linesAdded: diff.additions,
      linesRemoved: diff.deletions,
      diffText: diff.unifiedDiff
    };
  }
}
