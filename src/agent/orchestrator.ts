import fs from 'fs';
import path from 'path';
import { IModelProvider, ModelMessage } from '../models/provider.interface.js';
import { IHostAdapter } from '../adapters/hostAdapter.interface.js';
import { ToolRegistry } from '../tools/toolRegistry.js';
import { PathGuard } from '../security/pathGuard.js';
import { TargetAnalyzer } from '../security/targetAnalyzer.js';
import { BlastRadiusEstimator } from '../security/blastRadius.js';
import { RiskEngine } from '../security/riskEngine.js';
import { PolicyEngine } from '../permissions/policyEngine.js';
import { SnapshotManager } from '../verification/snapshotManager.js';
import { IntegrityVerifier } from '../verification/integrityVerifier.js';
import { DiffEngine, FileDiff } from '../verification/diffEngine.js';
import { SyntaxVerifier } from '../verification/syntaxVerifier.js';
import { RollbackManager } from '../verification/rollbackManager.js';
import { EvidenceLedger } from '../audit/evidenceLedger.js';
import { AuditLogger } from '../audit/auditLogger.js';
import { CodeGuardianConfig } from '../core/config.js';
import { CommandParser } from '../execution/commandParser.js';
import { CommandPolicy } from '../execution/commandPolicy.js';
import { SecureProcessExecutor } from '../execution/processExecutor.js';
import { ExecutableResolver } from '../execution/executableResolver.js';
import { NpmScriptAnalyzer } from '../execution/npmScriptAnalyzer.js';
import { CapabilityManager } from '../security/capabilities/capabilityManager.js';
import {
  ActionProposal,
  AuditRecord,
  ExecutionStatus,
  OperationType,
  SecurityEvaluation,
  UserDecisionType,
  CommandProposal,
  CapabilityGrant,
  ResolvedExecutable
} from '../core/types.js';

export interface OrchestrationResult {
  readonly summary: string;
  readonly iterations: number;
  readonly totalToolCalls: number;
  readonly totalModifications: number;
  readonly auditLogPath: string;
  readonly evidenceLogPath: string;
}

export class AgentOrchestrator {
  private readonly config: CodeGuardianConfig;
  private readonly modelProvider: IModelProvider;
  private readonly hostAdapter: IHostAdapter;
  private readonly toolRegistry: ToolRegistry;
  private readonly pathGuard: PathGuard;
  private readonly targetAnalyzer: TargetAnalyzer;
  private readonly blastRadiusEstimator: BlastRadiusEstimator;
  private readonly riskEngine: RiskEngine;
  private readonly policyEngine: PolicyEngine;
  private readonly snapshotManager: SnapshotManager;
  private readonly integrityVerifier: IntegrityVerifier;
  private readonly diffEngine: DiffEngine;
  private readonly syntaxVerifier: SyntaxVerifier;
  private readonly rollbackManager: RollbackManager;
  private readonly evidenceLedger: EvidenceLedger;
  private readonly auditLogger: AuditLogger;
  private readonly commandParser: CommandParser;
  private readonly commandPolicy: CommandPolicy;
  private readonly processExecutor: SecureProcessExecutor;
  private readonly executableResolver: ExecutableResolver;
  private readonly npmScriptAnalyzer: NpmScriptAnalyzer;
  private readonly capabilityManager: CapabilityManager;

  constructor(
    config: CodeGuardianConfig,
    modelProvider: IModelProvider,
    hostAdapter: IHostAdapter,
    dependencies?: {
      toolRegistry?: ToolRegistry;
      pathGuard?: PathGuard;
      targetAnalyzer?: TargetAnalyzer;
      blastRadiusEstimator?: BlastRadiusEstimator;
      riskEngine?: RiskEngine;
      policyEngine?: PolicyEngine;
      snapshotManager?: SnapshotManager;
      integrityVerifier?: IntegrityVerifier;
      diffEngine?: DiffEngine;
      syntaxVerifier?: SyntaxVerifier;
      rollbackManager?: RollbackManager;
      evidenceLedger?: EvidenceLedger;
      auditLogger?: AuditLogger;
      commandParser?: CommandParser;
      commandPolicy?: CommandPolicy;
      processExecutor?: SecureProcessExecutor;
      executableResolver?: ExecutableResolver;
      npmScriptAnalyzer?: NpmScriptAnalyzer;
      capabilityManager?: CapabilityManager;
    }
  ) {
    this.config = config;
    this.modelProvider = modelProvider;
    this.hostAdapter = hostAdapter;

    this.toolRegistry = dependencies?.toolRegistry || new ToolRegistry();
    this.pathGuard = dependencies?.pathGuard || new PathGuard(config.workspaceRoot);
    this.targetAnalyzer = dependencies?.targetAnalyzer || new TargetAnalyzer();
    this.blastRadiusEstimator = dependencies?.blastRadiusEstimator || new BlastRadiusEstimator();
    this.riskEngine = dependencies?.riskEngine || new RiskEngine();
    this.policyEngine = dependencies?.policyEngine || new PolicyEngine();
    this.snapshotManager = dependencies?.snapshotManager || new SnapshotManager(config.snapshotDir);
    this.integrityVerifier = dependencies?.integrityVerifier || new IntegrityVerifier();
    this.diffEngine = dependencies?.diffEngine || new DiffEngine();
    this.syntaxVerifier = dependencies?.syntaxVerifier || new SyntaxVerifier();
    this.rollbackManager = dependencies?.rollbackManager || new RollbackManager(this.snapshotManager);
    this.evidenceLedger = dependencies?.evidenceLedger || new EvidenceLedger(config.evidenceLogPath);
    this.auditLogger = dependencies?.auditLogger || new AuditLogger(config.auditLogPath);
    this.commandParser = dependencies?.commandParser || new CommandParser();
    this.commandPolicy = dependencies?.commandPolicy || new CommandPolicy();
    this.processExecutor = dependencies?.processExecutor || new SecureProcessExecutor(this.pathGuard);
    this.executableResolver = dependencies?.executableResolver || new ExecutableResolver(this.pathGuard);
    this.npmScriptAnalyzer = dependencies?.npmScriptAnalyzer || new NpmScriptAnalyzer(config.workspaceRoot, this.commandParser, this.commandPolicy);
    this.capabilityManager = dependencies?.capabilityManager || new CapabilityManager(config.workspaceRoot);
  }

  getEvidenceLedger(): EvidenceLedger {
    return this.evidenceLedger;
  }

  getRollbackManager(): RollbackManager {
    return this.rollbackManager;
  }

  getSyntaxVerifier(): SyntaxVerifier {
    return this.syntaxVerifier;
  }

  getDiffEngine(): DiffEngine {
    return this.diffEngine;
  }

  /**
   * Runs the governed agent loop against a specified prompt or objective.
   */
  async run(prompt: string): Promise<OrchestrationResult> {
    this.hostAdapter.notify('info', `CodeGuardian active for workspace: ${this.config.workspaceRoot}`);
    this.hostAdapter.notify('info', `Security model: Fail-Closed | Deterministic Gatekeeper enabled`);

    const history: ModelMessage[] = [
      {
        role: 'user',
        parts: [{ text: prompt }]
      }
    ];

    let iterations = 0;
    let totalToolCalls = 0;
    let totalModifications = 0;
    let finalSummary = '';

    const systemInstruction = `You are CodeGuardian, an expert software engineering assistant operating inside a governed security architecture.
Workspace Directory: ${this.config.workspaceRoot}

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. Every tool call you propose is intercepted and evaluated independently by the CodeGuardian deterministic security engine.
2. You CANNOT approve your own actions or declare that an action is safe.
3. Path containment is strictly enforced. Any attempt to traverse outside the workspace will be blocked.
4. Sensitive files (.env, private keys, credentials) are protected by policy.
5. All file modifications require valid syntax, pass independent verification, require user authorization, and are atomic.
6. Once your review and necessary fixes are complete, provide a comprehensive final text summary.`;

    while (iterations < this.config.maxIterations) {
      iterations++;
      this.hostAdapter.reportProgress(`Iteration ${iterations}/${this.config.maxIterations}: consulting model...`);

      const response = await this.modelProvider.generateContent({
        systemInstruction,
        history,
        tools: this.toolRegistry.getDeclarations()
      });

      // If model returned a final text answer and no tool calls, task is complete
      if (!response.toolCalls || response.toolCalls.length === 0) {
        finalSummary = response.text || 'Task completed with no further actions.';
        break;
      }

      // Preserve model response in history
      history.push({
        role: 'model',
        parts: response.text ? [{ text: response.text }] : [],
        raw: response.raw
      });

      // Process each proposed tool call through the Governed Security Pipeline
      for (const call of response.toolCalls) {
        totalToolCalls++;
        if (totalToolCalls > this.config.maxToolCalls) {
          this.hostAdapter.notify('warn', 'Maximum tool calls safety limit reached.');
          return {
            summary: 'Execution halted: Maximum tool calls limit reached.',
            iterations,
            totalToolCalls,
            totalModifications,
            auditLogPath: this.auditLogger.getLogFilePath(),
            evidenceLogPath: this.evidenceLedger.getLedgerFilePath()
          };
        }

        const actionId = `act_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
        const tool = this.toolRegistry.get(call.name);
        const operation: OperationType = tool ? tool.operation : 'UNKNOWN';
        const targetPath = this.toolRegistry.extractTargetPath(call.name, call.args);

        const proposal: ActionProposal = {
          actionId,
          toolName: call.name,
          operation,
          targetPath,
          parameters: call.args,
          reason: call.args.reason || `Proposed ${call.name} on ${targetPath || 'workspace'}`,
          sourceModel: this.modelProvider.name,
          timestamp: Date.now()
        };

        // 1. PATH GUARD & CANONICAL RESOLUTION
        const pathCheck = this.pathGuard.validate(targetPath || '.');

        // 2. TARGET SENSITIVITY ANALYSIS
        const sensitivityClassification = this.targetAnalyzer.classify(pathCheck.relativePath);

        // 3. BLAST RADIUS ESTIMATION
        const blastRadius = this.blastRadiusEstimator.estimate(
          operation,
          pathCheck.relativePath,
          sensitivityClassification.tier,
          pathCheck.allowed
        );

        const securityEval: SecurityEvaluation = {
          isWorkspaceContained: pathCheck.allowed,
          canonicalPath: pathCheck.canonicalPath,
          relativePath: pathCheck.relativePath,
          sensitivity: sensitivityClassification.tier,
          blastRadius,
          reversibility: operation === 'WRITE' ? 'REVERSIBLE' : 'IRREVERSIBLE',
          violations: pathCheck.allowed ? [] : [pathCheck.error || 'Outside workspace']
        };

        // 4. DETERMINISTIC RISK ENGINE EVALUATION
        let risk = this.riskEngine.evaluate({
          operation,
          sensitivity: securityEval.sensitivity,
          blastRadius,
          isWorkspaceContained: pathCheck.allowed,
          targetPath: pathCheck.relativePath
        });

        let userDecision: UserDecisionType | undefined = undefined;
        let executionStatus: ExecutionStatus = 'SUCCESS';
        let errorReason: string | undefined = undefined;
        let toolResponsePayload: any = null;
        let beforeHash: string | null = null;
        let afterHash: string | null = null;
        let fileDiff: FileDiff | undefined = undefined;
        let syntaxStatus: 'PASS' | 'FAIL' | 'SKIPPED' = 'SKIPPED';

        // 5. DETERMINISTIC POLICY ENGINE DECISION
        let policyDecision = this.policyEngine.evaluate({
          operation,
          targetPath: targetPath || '.',
          relativePath: pathCheck.relativePath,
          isWorkspaceContained: pathCheck.allowed,
          sensitivity: securityEval.sensitivity,
          blastRadius,
          risk
        });

        let capability: CapabilityGrant | undefined = undefined;

        // PROCESS EXECUTION INTERCEPTION
        if (operation === 'EXECUTE' || call.name === 'execute_command') {
          const rawCommand = String(call.args.command || '');
          const parsedCommand = this.commandParser.parse(rawCommand);
          let cmdPolicyEval = this.commandPolicy.evaluate(parsedCommand);

          // Record PROCESS_PROPOSED event in evidence ledger
          this.evidenceLedger.record('PROCESS_PROPOSED', {
            actionId,
            operation,
            target: pathCheck.relativePath || targetPath || 'N/A',
            provider: this.modelProvider.name,
            risk: { level: risk.level, score: risk.score },
            decision: policyDecision.decision,
            command: rawCommand,
            execution: 'PROPOSED',
            verification: 'SKIPPED'
          });

          // 1. Resolve executable path safely
          const resolved = this.executableResolver.resolve(parsedCommand.executable);
          this.evidenceLedger.record('EXECUTABLE_RESOLVED', {
            actionId,
            operation,
            target: resolved.resolvedPath,
            provider: this.modelProvider.name,
            risk: { level: 'LOW', score: 10 },
            decision: resolved.trusted ? 'ALLOW' : 'ASK_USER',
            command: rawCommand,
            details: {
              requestedName: resolved.requestedName,
              resolvedPath: resolved.resolvedPath,
              trusted: resolved.trusted,
              source: resolved.source
            }
          } as any);

          // Escalate decision to ASK_USER if executable is not trusted
          if (!resolved.trusted) {
            if (cmdPolicyEval.decision === 'ALLOW') {
              cmdPolicyEval = {
                decision: 'ASK_USER',
                matchedRule: 'PERM-EXEC-003-UNTRUSTED-EXECUTABLE',
                reason: `The executable "${resolved.requestedName}" is located in ${resolved.source} directory and is not trusted by default.`,
                riskLevel: 'HIGH',
                riskScore: 70
              };
            }
          }

          // 2. NPM script analysis
          if (parsedCommand.executable === 'npm') {
            const args = parsedCommand.args;
            let scriptName = '';
            if (args[0] === 'run' && args[1]) {
              scriptName = args[1];
            } else if (args[0] && args[0] !== 'run' && !args[0].startsWith('-')) {
              scriptName = args[0];
            }

            if (scriptName) {
              const scriptAnalysis = this.npmScriptAnalyzer.analyze(scriptName);
              
              this.evidenceLedger.record('SCRIPT_ANALYZED', {
                actionId,
                operation,
                target: `package.json#scripts.${scriptName}`,
                provider: this.modelProvider.name,
                risk: { level: scriptAnalysis.success ? 'LOW' : 'CRITICAL', score: scriptAnalysis.success ? 20 : 100 },
                decision: scriptAnalysis.success ? 'ALLOW' : 'BLOCK',
                command: rawCommand,
                details: {
                  scriptName,
                  chain: scriptAnalysis.chain,
                  success: scriptAnalysis.success,
                  error: scriptAnalysis.error
                }
              } as any);

              if (!scriptAnalysis.success) {
                cmdPolicyEval = {
                  decision: 'BLOCK',
                  matchedRule: scriptAnalysis.matchedRule || 'EXEC-005-MALICIOUS-NPM-SCRIPT',
                  reason: scriptAnalysis.error || `NPM script "${scriptName}" recursive checks failed.`,
                  riskLevel: 'CRITICAL',
                  riskScore: 100
                };
              } else if (scriptAnalysis.matchedRule) {
                // Escalate to ASK_USER if script analysis detected warnings
                cmdPolicyEval = {
                  decision: 'ASK_USER',
                  matchedRule: scriptAnalysis.matchedRule,
                  reason: scriptAnalysis.error || `NPM script "${scriptName}" contains custom arguments or unknown options.`,
                  riskLevel: (scriptAnalysis.riskLevel as any) || 'HIGH',
                  riskScore: scriptAnalysis.riskScore || 70
                };
              }
            }
          }

          // 3. Capability Grant Generation
          capability = this.capabilityManager.generateGrant('EXECUTE', cmdPolicyEval.decision);
          this.evidenceLedger.record('CAPABILITY_CREATED', {
            actionId,
            operation,
            target: capability.id,
            provider: this.modelProvider.name,
            risk: { level: cmdPolicyEval.riskLevel || 'LOW', score: cmdPolicyEval.riskScore || 20 },
            decision: cmdPolicyEval.decision,
            command: rawCommand,
            details: {
              capabilityId: capability.id,
              maxExecutionTimeMs: capability.maxExecutionTimeMs,
              maxOutputBytes: capability.maxOutputBytes,
              allowedPaths: capability.allowedPaths,
              deniedPaths: capability.deniedPaths
            }
          } as any);

          // Check if CommandPolicy blocks structurally
          if (cmdPolicyEval.decision === 'BLOCK') {
            executionStatus = 'BLOCKED';
            errorReason = cmdPolicyEval.reason;
            this.hostAdapter.notify('error', `BLOCKED Command by Policy [${cmdPolicyEval.matchedRule}]: ${cmdPolicyEval.reason}`);

            toolResponsePayload = {
              error: `SECURITY_POLICY_BLOCKED: Command execution blocked by rule [${cmdPolicyEval.matchedRule}]: ${cmdPolicyEval.reason}`
            };

            // Record blocked process in evidence ledger
            this.evidenceLedger.record('PROCESS_BLOCKED', {
              actionId,
              operation,
              target: pathCheck.relativePath || targetPath || 'N/A',
              provider: this.modelProvider.name,
              risk: { level: cmdPolicyEval.riskLevel, score: cmdPolicyEval.riskScore },
              decision: 'BLOCK',
              matchedRule: cmdPolicyEval.matchedRule,
              command: rawCommand,
              execution: 'BLOCKED',
              verification: 'SKIPPED',
              details: { reason: cmdPolicyEval.reason }
            });

            this.auditLogger.log({
              eventId: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
              timestamp: Date.now(),
              actionId,
              sourceModel: this.modelProvider.name,
              operation,
              target: pathCheck.relativePath || targetPath || 'N/A',
              risk: cmdPolicyEval.riskLevel,
              policyDecision: 'BLOCK',
              matchedRule: cmdPolicyEval.matchedRule,
              executionResult: 'BLOCKED',
              errorReason,
              verificationStatus: 'FAILED'
            });

            history.push({
              role: 'user',
              parts: [{
                toolResponse: {
                  name: call.name,
                  response: toolResponsePayload
                }
              }]
            });
            continue; // Move to next proposed tool call
          } else if (cmdPolicyEval.decision === 'ASK_USER') {
            // Upgrade risk and policyDecision details
            risk = {
              level: cmdPolicyEval.riskLevel,
              score: cmdPolicyEval.riskScore,
              factors: ['Command analysis: ' + cmdPolicyEval.matchedRule]
            };
            policyDecision = {
              decision: 'ASK_USER',
              matchedRule: cmdPolicyEval.matchedRule,
              reason: cmdPolicyEval.reason,
              requiresUserConfirmation: true
            };

            this.evidenceLedger.record('PROCESS_POLICY_DECISION', {
              actionId,
              operation,
              target: pathCheck.relativePath,
              provider: this.modelProvider.name,
              risk: { level: risk.level, score: risk.score },
              decision: 'ASK_USER',
              matchedRule: cmdPolicyEval.matchedRule,
              command: rawCommand,
              execution: 'ASK_USER',
              verification: 'SKIPPED'
            });
          } else if (cmdPolicyEval.decision === 'ALLOW') {
            risk = {
              level: cmdPolicyEval.riskLevel,
              score: cmdPolicyEval.riskScore,
              factors: ['Command analysis: ' + cmdPolicyEval.matchedRule]
            };
            policyDecision = {
              decision: 'ALLOW',
              matchedRule: cmdPolicyEval.matchedRule,
              reason: cmdPolicyEval.reason,
              requiresUserConfirmation: false
            };
          }
        }

        // PIPELINE CHECK 1: POLICY BLOCK
        if (policyDecision.decision === 'BLOCK') {
          executionStatus = 'BLOCKED';
          errorReason = policyDecision.reason;
          this.hostAdapter.notify('error', `BLOCKED by Policy [${policyDecision.matchedRule}]: ${policyDecision.reason}`);

          toolResponsePayload = {
            error: `SECURITY_POLICY_BLOCKED: ${policyDecision.reason}`
          };

          // Record blocked action in evidence ledger
          if (operation === 'EXECUTE') {
            this.evidenceLedger.record('PROCESS_BLOCKED', {
              actionId,
              operation,
              target: pathCheck.relativePath || targetPath || 'N/A',
              provider: this.modelProvider.name,
              risk: { level: risk.level, score: risk.score },
              decision: 'BLOCK',
              matchedRule: policyDecision.matchedRule,
              command: String(call.args.command || ''),
              execution: 'BLOCKED',
              verification: 'SKIPPED',
              details: { reason: policyDecision.reason }
            });
          } else {
            this.evidenceLedger.record('ACTION_BLOCKED', {
              actionId,
              operation,
              target: pathCheck.relativePath || targetPath || 'N/A',
              provider: this.modelProvider.name,
              risk: { level: risk.level, score: risk.score },
              decision: 'BLOCK',
              matchedRule: policyDecision.matchedRule,
              execution: 'BLOCKED',
              verification: 'SKIPPED',
              details: { reason: policyDecision.reason }
            });
          }
        }
        // PIPELINE CHECK 2: PRE-WRITE SYNTAX VERIFICATION & DIFF GENERATION (FOR WRITE OPERATIONS)
        else if (operation === 'WRITE') {
          const proposedContent = String(call.args.content ?? '');
          let originalContent: string | null = null;
          if (fs.existsSync(pathCheck.canonicalPath)) {
            try {
              originalContent = fs.readFileSync(pathCheck.canonicalPath, 'utf-8');
            } catch {
              // ignore
            }
          }

          // Generate structured diff metrics
          fileDiff = this.diffEngine.generateDiff(pathCheck.relativePath, originalContent, proposedContent);

          // Independent Syntax Verification
          const syntaxCheck = this.syntaxVerifier.verify(pathCheck.canonicalPath, proposedContent);
          syntaxStatus = syntaxCheck.status;

          if (syntaxCheck.status === 'FAIL') {
            executionStatus = 'FAILURE';
            const syntaxErrors = syntaxCheck.errors.map(e => `line ${e.line}:${e.column} - ${e.message}`);
            errorReason = `SYNTAX_VERIFICATION_FAILED: Proposed content contains syntax errors: ${syntaxErrors.join('; ')}`;
            this.hostAdapter.notify('error', `Syntax validation FAILED for ${pathCheck.relativePath}: ${syntaxErrors[0]}`);

            toolResponsePayload = { error: errorReason };

            // Record syntax failure in evidence ledger
            this.evidenceLedger.record('SYNTAX_VERIFICATION_FAILED', {
              actionId,
              operation,
              target: pathCheck.relativePath,
              provider: this.modelProvider.name,
              risk: { level: risk.level, score: risk.score },
              decision: policyDecision.decision,
              matchedRule: policyDecision.matchedRule,
              originalSha256: fileDiff.originalHash,
              proposedSha256: fileDiff.proposedHash,
              syntax: 'FAIL',
              execution: 'FAILURE',
              verification: 'FAILED',
              details: { syntaxErrors }
            });

            this.auditLogger.log({
              eventId: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
              timestamp: Date.now(),
              actionId,
              sourceModel: this.modelProvider.name,
              operation,
              target: pathCheck.relativePath,
              risk: risk.level,
              policyDecision: policyDecision.decision,
              matchedRule: policyDecision.matchedRule,
              executionResult: 'FAILURE',
              errorReason,
              verificationStatus: 'FAILED'
            });

            // Send error feedback directly back to model so it can fix syntax
            history.push({
              role: 'user',
              parts: [{
                toolResponse: {
                  name: call.name,
                  response: toolResponsePayload
                }
              }]
            });
            continue;
          }
        }

        // PIPELINE CHECK 3: USER CONFIRMATION REQUIRED
        if (policyDecision.decision === 'ASK_USER' && executionStatus === 'SUCCESS') {
          userDecision = await this.hostAdapter.askUserConfirmation({
            action: proposal,
            security: securityEval,
            risk,
            policy: policyDecision,
            diff: fileDiff ? {
              filePath: fileDiff.filePath,
              linesAdded: fileDiff.additions,
              linesRemoved: fileDiff.deletions,
              diffText: fileDiff.unifiedDiff
            } : undefined
          });

          if (userDecision === 'DENY') {
            executionStatus = 'DENIED';
            errorReason = 'User explicitly denied authorization.';
            this.hostAdapter.notify('warn', `Action DENIED by user: ${targetPath}`);

            toolResponsePayload = {
              error: 'USER_PERMISSION_DENIED: The user declined authorization for this modification.'
            };

            if (operation === 'EXECUTE') {
              this.evidenceLedger.record('PROCESS_BLOCKED', {
                actionId,
                operation,
                target: pathCheck.relativePath,
                provider: this.modelProvider.name,
                risk: { level: risk.level, score: risk.score },
                decision: 'ASK_USER',
                matchedRule: policyDecision.matchedRule,
                userDecision: 'DENY',
                command: String(call.args.command || ''),
                execution: 'DENIED',
                verification: 'SKIPPED'
              });
            } else {
              this.evidenceLedger.record('USER_PERMISSION_DENIED', {
                actionId,
                operation,
                target: pathCheck.relativePath,
                provider: this.modelProvider.name,
                risk: { level: risk.level, score: risk.score },
                decision: 'ASK_USER',
                matchedRule: policyDecision.matchedRule,
                userDecision: 'DENY',
                originalSha256: fileDiff?.originalHash,
                proposedSha256: fileDiff?.proposedHash,
                syntax: syntaxStatus,
                execution: 'DENIED',
                verification: 'SKIPPED'
              });
            }
          } else if (userDecision === 'ALLOW_SESSION') {
            this.policyEngine.getSessionStore().grant(operation, pathCheck.relativePath);
          }
        }

        // PIPELINE CHECK 4: EXECUTION & POST-WRITE VERIFICATION
        if (executionStatus === 'SUCCESS') {
          if (!tool) {
            executionStatus = 'FAILURE';
            errorReason = `Tool not registered: ${call.name}`;
            toolResponsePayload = { error: errorReason };
          } else {
            // Check file modification limits
            if (operation === 'WRITE' && totalModifications >= this.config.maxFileModifications) {
              executionStatus = 'BLOCKED';
              errorReason = 'Maximum file modifications limit reached.';
              toolResponsePayload = { error: errorReason };
            } else {
               const execResult = await tool.execute(call.args, {
                 workspaceRoot: this.config.workspaceRoot,
                 snapshotManager: this.snapshotManager,
                 integrityVerifier: this.integrityVerifier,
                 rollbackManager: this.rollbackManager,
                 syntaxVerifier: this.syntaxVerifier,
                 commandParser: this.commandParser,
                 commandPolicy: this.commandPolicy,
                 processExecutor: this.processExecutor,
                 capability: capability
               });

               if (capability && operation === 'EXECUTE') {
                 if (execResult.error && execResult.error.includes('Capability violation')) {
                   this.evidenceLedger.record('CAPABILITY_VIOLATION', {
                     actionId,
                     operation,
                     target: capability.id,
                     provider: this.modelProvider.name,
                     risk: { level: 'CRITICAL', score: 100 },
                     decision: policyDecision.decision,
                     command: String(call.args.command || ''),
                     details: {
                       capabilityId: capability.id,
                       error: execResult.error
                     }
                   } as any);
                 } else {
                   this.evidenceLedger.record('CAPABILITY_USED', {
                     actionId,
                     operation,
                     target: capability.id,
                     provider: this.modelProvider.name,
                     risk: { level: risk.level, score: risk.score },
                     decision: policyDecision.decision,
                     command: String(call.args.command || ''),
                     details: {
                       capabilityId: capability.id,
                       success: execResult.success
                     }
                   } as any);
                 }
               }

               if (execResult.success) {
                 executionStatus = 'SUCCESS';
                 toolResponsePayload = execResult.data;
                 if (operation === 'WRITE') {
                   totalModifications++;
                   beforeHash = execResult.data?.beforeHash || null;
                   afterHash = execResult.data?.afterHash || null;

                   // Append verified modification to tamper-evident evidence ledger
                   this.evidenceLedger.record('ACTION_VERIFIED', {
                     actionId,
                     operation,
                     target: pathCheck.relativePath,
                     provider: this.modelProvider.name,
                     risk: { level: risk.level, score: risk.score },
                     decision: policyDecision.decision,
                     matchedRule: policyDecision.matchedRule,
                     userDecision,
                     originalSha256: beforeHash || undefined,
                     proposedSha256: afterHash || undefined,
                     finalSha256: afterHash || undefined,
                     diffSummary: fileDiff ? {
                       additions: fileDiff.additions,
                       deletions: fileDiff.deletions,
                       changedLines: fileDiff.changedLines
                     } : undefined,
                     syntax: syntaxStatus,
                     execution: 'SUCCESS',
                     verification: 'PASS'
                   });
                 } else if (operation === 'EXECUTE') {
                   // Record child process spawn details
                   if (execResult.data?.exitCode !== null) {
                     this.evidenceLedger.record('PROCESS_CHILD_CREATED', {
                       actionId,
                       operation,
                       target: pathCheck.relativePath,
                       provider: this.modelProvider.name,
                       risk: { level: 'LOW', score: 10 },
                       decision: 'ALLOW',
                       command: execResult.data?.command,
                       details: { exitCode: execResult.data?.exitCode }
                     } as any);
                     this.evidenceLedger.record('PROCESS_CHILD_TERMINATED', {
                       actionId,
                       operation,
                       target: pathCheck.relativePath,
                       provider: this.modelProvider.name,
                       risk: { level: 'LOW', score: 10 },
                       decision: 'ALLOW',
                       command: execResult.data?.command,
                       details: { exitCode: execResult.data?.exitCode }
                     } as any);
                   }

                   this.evidenceLedger.record('PROCESS_COMPLETED', {
                     actionId,
                     operation,
                     target: pathCheck.relativePath,
                     provider: this.modelProvider.name,
                     risk: { level: risk.level, score: risk.score },
                     decision: policyDecision.decision,
                     matchedRule: policyDecision.matchedRule,
                     userDecision,
                     command: execResult.data?.command,
                     exitCode: execResult.data?.exitCode,
                     signal: execResult.data?.signal,
                     durationMs: execResult.data?.durationMs,
                     stdoutHash: execResult.data?.stdoutHash,
                     stderrHash: execResult.data?.stderrHash,
                     timedOut: execResult.data?.timedOut,
                     execution: 'SUCCESS',
                     verification: 'PASS'
                   });
                 }
               } else {
                 executionStatus = 'FAILURE';
                 errorReason = execResult.error;
                 toolResponsePayload = { error: execResult.error };

                 if (operation === 'WRITE') {
                   this.evidenceLedger.record('MODIFICATION_FAILED_ROLLED_BACK', {
                     actionId,
                     operation,
                     target: pathCheck.relativePath,
                     provider: this.modelProvider.name,
                     risk: { level: risk.level, score: risk.score },
                     decision: policyDecision.decision,
                     matchedRule: policyDecision.matchedRule,
                     userDecision,
                     originalSha256: fileDiff?.originalHash,
                     proposedSha256: fileDiff?.proposedHash,
                     syntax: syntaxStatus,
                     execution: 'FAILURE',
                     verification: 'FAILED',
                     rollback: {
                       attempted: true,
                       verified: true,
                       error: execResult.error
                     },
                     details: { errorReason }
                   });
                 } else if (operation === 'EXECUTE') {
                   const eventName = execResult.data?.timedOut ? 'PROCESS_TIMEOUT' : 'PROCESS_COMPLETED';
                   this.evidenceLedger.record(eventName, {
                     actionId,
                     operation,
                     target: pathCheck.relativePath,
                     provider: this.modelProvider.name,
                     risk: { level: risk.level, score: risk.score },
                     decision: policyDecision.decision,
                     matchedRule: policyDecision.matchedRule,
                     userDecision,
                     command: execResult.data?.command || String(call.args.command || ''),
                     exitCode: execResult.data?.exitCode ?? null,
                     signal: execResult.data?.signal ?? null,
                     durationMs: execResult.data?.durationMs ?? 0,
                     stdoutHash: execResult.data?.stdoutHash,
                     stderrHash: execResult.data?.stderrHash,
                     timedOut: !!execResult.data?.timedOut,
                     execution: 'FAILURE',
                     verification: 'FAIL',
                     details: { error: execResult.error }
                   });
                 }
               }
            }
          }
        }

        // 6. RECORD STRUCTURED AUDIT RECORD
        const auditRecord: AuditRecord = {
          eventId: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
          timestamp: Date.now(),
          actionId,
          sourceModel: this.modelProvider.name,
          operation,
          target: pathCheck.relativePath || targetPath || 'N/A',
          risk: risk.level,
          policyDecision: policyDecision.decision,
          matchedRule: policyDecision.matchedRule,
          userDecision,
          executionResult: executionStatus,
          beforeHash,
          afterHash,
          errorReason,
          verificationStatus: executionStatus === 'SUCCESS' ? 'VERIFIED' : 'FAILED'
        };

        this.auditLogger.log(auditRecord);

        // Feed tool result back into history
        history.push({
          role: 'user',
          parts: [
            {
              toolResponse: {
                name: call.name,
                response: toolResponsePayload
              }
            }
          ]
        });
      }
    }

    return {
      summary: finalSummary || 'Agent session reached iteration threshold.',
      iterations,
      totalToolCalls,
      totalModifications,
      auditLogPath: this.auditLogger.getLogFilePath(),
      evidenceLogPath: this.evidenceLedger.getLedgerFilePath()
    };
  }
}
