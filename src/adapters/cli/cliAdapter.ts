import readline from 'readline';
import { IHostAdapter } from '../hostAdapter.interface.js';
import { PermissionRequest, UserDecisionType } from '../../core/types.js';

export class CliAdapter implements IHostAdapter {
  private presetDecision?: UserDecisionType;

  constructor(presetDecision?: UserDecisionType) {
    this.presetDecision = presetDecision;
  }

  setPresetDecision(decision?: UserDecisionType): void {
    this.presetDecision = decision;
  }

  async askUserConfirmation(request: PermissionRequest): Promise<UserDecisionType> {
    // If running in automated/test mode with an explicit preset decision
    if (this.presetDecision) {
      this.renderPrompt(request);
      console.log(`[Auto-Selected]: ${this.presetDecision}\n`);
      return this.presetDecision;
    }

    // Interactive CLI mode
    this.renderPrompt(request);

    // If stdin is not a TTY (e.g. non-interactive script), default to DENY (fail closed)
    if (!process.stdin.isTTY) {
      console.log('Non-interactive environment detected. Defaulting to DENY (fail closed).\n');
      return 'DENY';
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    return new Promise<UserDecisionType>((resolve) => {
      const ask = () => {
        rl.question('Selection (A/S/D): ', (answer) => {
          const trimmed = answer.trim().toUpperCase();
          if (trimmed === 'A') {
            rl.close();
            resolve('ALLOW_ONCE');
          } else if (trimmed === 'S') {
            rl.close();
            resolve('ALLOW_SESSION');
          } else if (trimmed === 'D' || trimmed === '') {
            rl.close();
            resolve('DENY');
          } else {
            console.log('Invalid input. Please enter A, S, or D.');
            ask();
          }
        });
      };

      ask();
    });
  }

  private renderPrompt(request: PermissionRequest): void {
    const { action, risk, diff } = request;
    const target = action.targetPath || 'N/A';
    const reason = action.reason || 'AI agent requested file modification';

    console.log('\n========================================');
    console.log('🔐 CODEGUARDIAN PERMISSION REQUEST');
    console.log('========================================');
    console.log(`Action: ${action.operation}`);
    console.log(`Target: ${target}`);
    console.log(`Risk:   ${risk.level} (Score: ${risk.score})`);
    console.log(`\nReason:\n${reason}`);

    if (diff) {
      console.log('\nChanges:');
      console.log(`+${diff.linesAdded} lines`);
      console.log(`-${diff.linesRemoved} lines`);
      if (diff.diffText) {
        console.log('\nDiff Preview:');
        console.log(diff.diffText);
      }
    }

    console.log('========================================');
    console.log('Allow this action?');
    console.log('[A] Allow once');
    console.log('[S] Allow for this session');
    console.log('[D] Deny');
    console.log('========================================\n');
  }

  notify(level: 'info' | 'warn' | 'error', message: string): void {
    const prefix = {
      info: 'ℹ️ ',
      warn: '⚠️ ',
      error: '❌'
    }[level];
    console.log(`${prefix} ${message}`);
  }

  reportProgress(message: string): void {
    console.log(`⚡ ${message}`);
  }
}
