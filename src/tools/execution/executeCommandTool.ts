import crypto from 'crypto';
import { ITool, ToolSchema, ToolExecutionContext } from '../tool.interface.js';
import { OperationType, ToolResult, CommandProposal } from '../../core/types.js';

export class ExecuteCommandTool implements ITool {
  readonly name = 'execute_command';
  readonly description = 'Executes approved verification commands in the project workspace (e.g., tests, linters, builds).';
  readonly operation: OperationType = 'EXECUTE';

  readonly parameters: ToolSchema = {
    type: 'object',
    properties: {
      command: {
        type: 'string',
        description: 'The command string to execute (e.g., "npm test").'
      },
      working_directory: {
        type: 'string',
        description: 'The relative or absolute subdirectory to run the command in. Defaults to workspace root.'
      },
      purpose: {
        type: 'string',
        description: 'The purpose of the command execution.',
        enum: ['TEST', 'LINT', 'BUILD', 'TYPECHECK', 'OTHER']
      }
    },
    required: ['command', 'purpose']
  };

  async execute(args: Record<string, any>, context: ToolExecutionContext): Promise<ToolResult> {
    const startTime = Date.now();

    if (!args.command || typeof args.command !== 'string') {
      return {
        success: false,
        error: 'Command must be a valid string.',
        executionTimeMs: Date.now() - startTime
      };
    }

    if (!context.processExecutor || !context.commandParser || !context.commandPolicy) {
      return {
        success: false,
        error: 'Execution engine components are not configured in the current context.',
        executionTimeMs: Date.now() - startTime
      };
    }

    try {
      const workingDir = args.working_directory || context.workspaceRoot;
      const cmdProposal: CommandProposal = {
        command: args.command,
        workingDirectory: workingDir,
        purpose: args.purpose || 'OTHER',
        requestedBy: 'AGENT'
      };

      const parsed = context.commandParser.parse(cmdProposal.command);
      const policyEval = context.commandPolicy.evaluate(parsed);

      if (policyEval.decision === 'BLOCK') {
        return {
          success: false,
          error: `SECURITY_POLICY_BLOCKED: Command execution blocked by rule [${policyEval.matchedRule}]: ${policyEval.reason}`,
          executionTimeMs: Date.now() - startTime
        };
      }

      // Execute safely
      const result = await context.processExecutor.execute(
        cmdProposal,
        parsed,
        policyEval.decision,
        context.capability
      );

      // Compute hashes of output rather than storing massive logs in results/ledger
      const stdoutHash = crypto.createHash('sha256').update(result.stdout, 'utf-8').digest('hex');
      const stderrHash = crypto.createHash('sha256').update(result.stderr, 'utf-8').digest('hex');

      return {
        success: result.exitCode === 0 && !result.timedOut,
        data: {
          command: result.command,
          exitCode: result.exitCode,
          signal: result.signal,
          stdout: result.stdout,
          stderr: result.stderr,
          stdoutHash,
          stderrHash,
          timedOut: result.timedOut,
          durationMs: result.durationMs,
          observedProcesses: result.observedProcesses,
          observedNetwork: result.observedNetwork
        },
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: any) {
      return {
        success: false,
        error: `Process execution failed: ${err.message}`,
        executionTimeMs: Date.now() - startTime
      };
    }
  }
}
