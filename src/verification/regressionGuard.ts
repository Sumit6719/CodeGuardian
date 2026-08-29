import fs from 'fs';
import path from 'path';
import { IsolationFactory } from '../security/isolation/isolationFactory.js';
import { IsolationPolicy } from '../security/isolation/isolationTypes.js';
import { CapabilityManager } from '../security/capabilities/capabilityManager.js';
import { RollbackManager } from './rollbackManager.js';
import { EvidenceLedger } from '../audit/evidenceLedger.js';
import { ChangeSnapshot } from '../core/types.js';

export interface RegressionTestResult {
  readonly success: boolean;
  readonly runner: string;
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly rolledBack: boolean;
  readonly error?: string;
}

export class RegressionGuard {
  private readonly workspaceRoot: string;
  private readonly isolationFactory: IsolationFactory;
  private readonly capabilityManager: CapabilityManager;
  private readonly rollbackManager: RollbackManager;
  private readonly evidenceLedger: EvidenceLedger;

  constructor(
    workspaceRoot: string,
    isolationFactory: IsolationFactory,
    capabilityManager: CapabilityManager,
    rollbackManager: RollbackManager,
    evidenceLedger: EvidenceLedger
  ) {
    this.workspaceRoot = workspaceRoot;
    this.isolationFactory = isolationFactory;
    this.capabilityManager = capabilityManager;
    this.rollbackManager = rollbackManager;
    this.evidenceLedger = evidenceLedger;
  }

  /**
   * Deterministically detects the supported project test runner from workspace metadata.
   */
  detectTestRunner(): { executable: string; args: string[]; runner: string } | null {
    const pkgPath = path.join(this.workspaceRoot, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        if (pkg.scripts && pkg.scripts.test) {
          return { executable: 'npm', args: ['test'], runner: 'npm-test' };
        }
      } catch {
        // ignore
      }
    }

    if (fs.existsSync(path.join(this.workspaceRoot, 'pytest.ini')) || fs.existsSync(path.join(this.workspaceRoot, 'conftest.py'))) {
      return { executable: 'pytest', args: [], runner: 'pytest' };
    }

    if (fs.existsSync(path.join(this.workspaceRoot, 'Cargo.toml'))) {
      return { executable: 'cargo', args: ['test'], runner: 'cargo-test' };
    }

    return null;
  }

  /**
   * Executes project regression tests post-modification inside an OS isolation sandbox.
   * If tests fail, automatically rolls back changes and records evidence.
   */
  async runRegressionCheck(snapshot?: ChangeSnapshot): Promise<RegressionTestResult> {
    // Prevent recursive loop if regression guard is already active
    if (process.env.CODEGUARDIAN_REGRESSION_ACTIVE === 'true') {
      return {
        success: true,
        runner: 'recursion-guard',
        exitCode: 0,
        stdout: 'Skipped to prevent recursive test loop.',
        stderr: '',
        rolledBack: false
      };
    }

    const runnerInfo = this.detectTestRunner();
    if (!runnerInfo) {
      return {
        success: true,
        runner: 'none',
        exitCode: 0,
        stdout: 'No project test runner detected.',
        stderr: '',
        rolledBack: false
      };
    }

    // Set anti-recursion flag during test execution
    process.env.CODEGUARDIAN_REGRESSION_ACTIVE = 'true';

    const capability = this.capabilityManager.generateGrant('EXECUTE', 'ALLOW', {
      allowedPaths: [this.workspaceRoot],
      allowNetwork: false,
      allowedProcesses: [runnerInfo.executable, 'node', 'npx', 'tsc']
    });

    const isolationPolicy: IsolationPolicy = {
      requiredLevel: 'PROCESS',
      networkPolicy: { mode: 'NONE' },
      resourceLimits: { maxExecutionTimeMs: 60000, maxOutputBytes: 100 * 1024 },
      filesystemPolicy: { mode: 'RESTRICTED_WRITE', allowedWritePaths: [this.workspaceRoot], deniedPaths: [] }
    };

    let sandboxEnv: any = null;
    let rolledBack = false;

    try {
      sandboxEnv = await this.isolationFactory.createEnvironment(isolationPolicy, capability);

      const execResult = await sandboxEnv.execute(
        {
          command: `${runnerInfo.executable} ${runnerInfo.args.join(' ')}`.trim(),
          workingDirectory: this.workspaceRoot,
          purpose: 'TEST',
          requestedBy: 'SYSTEM'
        },
        {
          rawCommand: `${runnerInfo.executable} ${runnerInfo.args.join(' ')}`.trim(),
          executable: runnerInfo.executable,
          args: runnerInfo.args,
          env: {},
          hasShellOperators: false,
          isDangerous: false
        },
        capability
      );

      const testPassed = execResult.exitCode === 0;

      if (testPassed) {
        this.evidenceLedger.record('REGRESSION_CHECK_PASSED', {
          actionId: `act_reg_${Date.now()}`,
          operation: 'EXECUTE',
          target: runnerInfo.runner,
          provider: 'RegressionGuard',
          risk: { level: 'LOW', score: 10 },
          decision: 'ALLOW',
          details: { runner: runnerInfo.runner, exitCode: execResult.exitCode }
        } as any);

        return {
          success: true,
          runner: runnerInfo.runner,
          exitCode: execResult.exitCode,
          stdout: execResult.stdout,
          stderr: execResult.stderr,
          rolledBack: false
        };
      } else {
        this.evidenceLedger.record('REGRESSION_DETECTED', {
          actionId: `act_reg_${Date.now()}`,
          operation: 'EXECUTE',
          target: runnerInfo.runner,
          provider: 'RegressionGuard',
          risk: { level: 'HIGH', score: 80 },
          decision: 'BLOCK',
          details: { runner: runnerInfo.runner, exitCode: execResult.exitCode, error: execResult.stderr }
        } as any);

        if (snapshot) {
          const rollbackRes = this.rollbackManager.rollback(snapshot);
          rolledBack = rollbackRes.success;
          this.evidenceLedger.record('EFFECT_ROLLBACK_COMPLETED', {
            actionId: `act_reg_rb_${Date.now()}`,
            operation: 'WRITE',
            target: snapshot.filePath,
            provider: 'RegressionGuard',
            risk: { level: 'LOW', score: 10 },
            decision: 'ALLOW',
            details: { snapshotId: snapshot.snapshotId, verified: rollbackRes.verified }
          } as any);
        }

        return {
          success: false,
          runner: runnerInfo.runner,
          exitCode: execResult.exitCode,
          stdout: execResult.stdout,
          stderr: execResult.stderr,
          rolledBack,
          error: `Regression tests failed with exit code ${execResult.exitCode}.`
        };
      }
    } catch (err: any) {
      return {
        success: false,
        runner: runnerInfo.runner,
        exitCode: null,
        stdout: '',
        stderr: err.message,
        rolledBack: false,
        error: err.message
      };
    } finally {
      process.env.CODEGUARDIAN_REGRESSION_ACTIVE = 'false';
      if (sandboxEnv) {
        try {
          await sandboxEnv.destroy();
        } catch {
          // ignore
        }
      }
    }
  }
}
