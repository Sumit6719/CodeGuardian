import path from 'path';
import 'dotenv/config';

// Core exports
export * from './core/types.js';
export * from './core/errors.js';
export * from './core/config.js';
export * from './core/eventBus.js';

// Security exports
export * from './security/pathGuard.js';
export * from './security/targetAnalyzer.js';
export * from './security/blastRadius.js';
export * from './security/riskEngine.js';

// Permission exports
export * from './permissions/policy.interface.js';
export * from './permissions/defaultPolicies.js';
export * from './permissions/policyEngine.js';
export * from './permissions/sessionStore.js';

// Verification & Tools exports
export * from './verification/snapshotManager.js';
export * from './verification/integrityVerifier.js';
export * from './verification/diffGenerator.js';
export * from './verification/diffEngine.js';
export * from './verification/changeContract.js';
export * from './verification/syntaxVerifier.js';
export * from './verification/rollbackManager.js';
export * from './tools/tool.interface.js';
export * from './tools/toolRegistry.js';
export * from './tools/filesystem/listFilesTool.js';
export * from './tools/filesystem/readFileTool.js';
export * from './tools/filesystem/writeFileTool.js';
export * from './tools/execution/executeCommandTool.js';

// Execution & Isolation exports
export * from './execution/commandParser.js';
export * from './execution/commandPolicy.js';
export * from './execution/processExecutor.js';
export * from './execution/executableResolver.js';
export * from './execution/npmScriptAnalyzer.js';
export * from './security/capabilities/capabilityManager.js';
export * from './security/effects/effectTypes.js';
export * from './security/effects/effectObserver.js';
export * from './security/effects/effectFirewall.js';
export * from './security/effects/changeImpact.js';
export * from './security/isolation/isolationTypes.js';
export * from './security/isolation/isolationProvider.interface.js';
export * from './security/isolation/containerProvider.js';
export * from './security/isolation/processProvider.js';
export * from './security/isolation/hostFallbackProvider.js';
export * from './security/isolation/isolationFactory.js';
export * from './security/isolation/networkPolicy.js';
export * from './security/stateMachine/securityStateMachine.js';

// Audit, Models & VS Code exports
export * from './audit/auditLogger.js';
export * from './audit/evidenceLedger.js';
export * from './adapters/hostAdapter.interface.js';
export * from './adapters/cli/cliAdapter.js';
export * from './models/provider.interface.js';
export * from './models/providers/geminiProvider.js';
export * from './models/providers/claudeProvider.js';
export * from './models/providers/openAIProvider.js';
export * from './models/providers/ollamaProvider.js';
export * from './models/modelRegistry.js';
export * from './models/disagreement.js';
export * from './verification/regressionGuard.js';
export * from './vscode/webviewProtocol.js';
export * from './vscode/extensionBridge.js';
export * from './vscode/webviewPanelController.js';
export * from './project/workspaceContext.js';
export * from './agent/orchestrator.js';

import { createDefaultConfig } from './core/config.js';
import { GeminiProvider } from './models/providers/geminiProvider.js';
import { CliAdapter } from './adapters/cli/cliAdapter.js';
import { AgentOrchestrator } from './agent/orchestrator.js';
import { WorkspaceContext } from './project/workspaceContext.js';

/**
 * CLI execution entrypoint
 */
export async function main() {
  const targetDir = process.argv[2] || '.';
  const workspaceRoot = path.resolve(targetDir);

  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║              🛡️  CODEGUARDIAN v0.6.0                    ║');
  console.log('║   Multi-Model Independence & VS Code Integration System  ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`\n📂 Target Workspace: ${workspaceRoot}`);

  if (!process.env.GEMINI_API_KEY) {
    console.error('\n❌ ERROR: GEMINI_API_KEY environment variable is not set.');
    console.error('Please configure GEMINI_API_KEY in your .env file or environment.');
    process.exit(1);
  }

  const wsContext = new WorkspaceContext(workspaceRoot);
  const summary = wsContext.getSummary();
  console.log(`📊 Discovered ${summary.totalFiles} project files (Git repository: ${summary.hasGit ? 'YES' : 'NO'})\n`);

  const config = createDefaultConfig(workspaceRoot);
  const modelProvider = new GeminiProvider();
  const hostAdapter = new CliAdapter();
  const orchestrator = new AgentOrchestrator(config, modelProvider, hostAdapter);

  const goal = process.argv[3] || `Analyze all source files in ${workspaceRoot}, perform security and quality code review, and fix critical bugs if permitted.`;

  try {
    const result = await orchestrator.run(goal);
    console.log('\n========================================');
    console.log('📋 EXECUTION SUMMARY');
    console.log('========================================');
    console.log(result.summary);
    console.log(`\n• Iterations:     ${result.iterations}`);
    console.log(`• Tool Calls:     ${result.totalToolCalls}`);
    console.log(`• Modifications:  ${result.totalModifications}`);
    console.log(`• Audit Trail:    ${result.auditLogPath}`);
    console.log('========================================\n');
  } catch (err: any) {
    console.error(`\n❌ Execution halted with error: ${err.message}`);
    process.exit(1);
  }
}

// Auto-run if executed as main module
const isMain = process.argv[1] && (
  process.argv[1].endsWith('index.ts') ||
  process.argv[1].endsWith('index.js')
);

if (isMain) {
  main().catch(err => {
    console.error('Unhandled fatal error:', err);
    process.exit(1);
  });
}
