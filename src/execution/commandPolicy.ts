import { ParsedCommand } from './commandParser.js';
import { CommandDecision, RiskLevel } from '../core/types.js';

export interface CommandPolicyEvaluation {
  readonly decision: CommandDecision;
  readonly matchedRule: string;
  readonly reason: string;
  readonly riskLevel: RiskLevel;
  readonly riskScore: number;
}

export class CommandPolicy {
  /**
   * Evaluates a parsed command against security policies and allowlists.
   */
  evaluate(parsed: ParsedCommand): CommandPolicyEvaluation {
    // 1. Structural parser block checks
    if (parsed.isDangerous) {
      const reason = parsed.dangerReason || 'Dangerous command structure detected.';

      // Route specific danger types
      if (parsed.rawCommand.includes('npm install') || parsed.rawCommand.includes('yarn add') || parsed.rawCommand.includes('pnpm add') || parsed.rawCommand.includes('npm i') || parsed.rawCommand.includes('npm update') || parsed.rawCommand.includes('npm upgrade')) {
        return {
          decision: 'ASK_USER',
          matchedRule: 'EXEC-004-PACKAGE-INSTALLATION',
          reason: 'Package installations and updates require explicit user verification.',
          riskLevel: 'HIGH',
          riskScore: 75
        };
      }

      if (parsed.hasShellOperators) {
        return {
          decision: 'BLOCK',
          matchedRule: 'EXEC-003-SHELL-CHAINING',
          reason: 'Command chaining, piping, or redirections are strictly blocked to prevent command injection.',
          riskLevel: 'CRITICAL',
          riskScore: 100
        };
      }

      return {
        decision: 'BLOCK',
        matchedRule: 'EXEC-001-DANGEROUS-COMMAND',
        reason,
        riskLevel: 'CRITICAL',
        riskScore: 100
      };
    }

    // 2. Initial Command Allowlist
    const exec = parsed.executable;
    const args = parsed.args;

    if (exec === 'npm') {
      const joinedArgs = args.join(' ');
      // Exact allowlist matches
      if (
        joinedArgs === 'test' ||
        joinedArgs === 'run test' ||
        joinedArgs === 'run lint' ||
        joinedArgs === 'run build' ||
        joinedArgs === 'run typecheck'
      ) {
        return {
          decision: 'ALLOW',
          matchedRule: 'PERM-EXEC-001-SAFE-VERIFICATION',
          reason: `Safe verification command allowed: ${parsed.rawCommand}`,
          riskLevel: 'LOW',
          riskScore: 20
        };
      }

      // Safe verification prefixes with additional arguments
      if (
        args[0] === 'test' ||
        (args[0] === 'run' && ['test', 'lint', 'build', 'typecheck'].includes(args[1]))
      ) {
        return {
          decision: 'ASK_USER',
          matchedRule: 'PERM-EXEC-002-VERIFICATION-WITH-OPTIONS',
          reason: `Verification command contains custom options or arguments: ${parsed.rawCommand}`,
          riskLevel: 'MEDIUM',
          riskScore: 40
        };
      }
    }

    if (exec === 'npx') {
      const joinedArgs = args.join(' ');
      if (joinedArgs === 'tsc --noEmit' || joinedArgs === 'tsc') {
        return {
          decision: 'ALLOW',
          matchedRule: 'PERM-EXEC-001-SAFE-VERIFICATION',
          reason: `Safe verification command allowed: ${parsed.rawCommand}`,
          riskLevel: 'LOW',
          riskScore: 20
        };
      }
    }

    // 3. Fallback for benign-looking but unknown commands (e.g. git status)
    return {
      decision: 'ASK_USER',
      matchedRule: 'EXEC-900-UNKNOWN-COMMAND-CONFIRMATION',
      reason: `Unknown or un-allowlisted command execution requested: ${parsed.rawCommand}`,
      riskLevel: 'HIGH',
      riskScore: 65
    };
  }
}
