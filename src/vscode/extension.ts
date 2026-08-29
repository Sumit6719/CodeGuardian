import path from 'path';
import { createDefaultConfig } from '../core/config.js';
import { GeminiProvider } from '../models/providers/geminiProvider.js';
import { ClaudeProvider } from '../models/providers/claudeProvider.js';
import { OpenAIProvider } from '../models/providers/openAIProvider.js';
import { OllamaProvider } from '../models/providers/ollamaProvider.js';
import { ModelProviderRegistry } from '../models/modelRegistry.js';
import { AgentOrchestrator } from '../agent/orchestrator.js';
import { ExtensionHostBridge } from './extensionBridge.js';
import { WebviewPanelController } from './webviewPanelController.js';
import { getWebviewHtml } from './webviewContent.js';
import { IHostAdapter } from '../adapters/hostAdapter.interface.js';
import { PermissionRequest, UserDecisionType } from '../core/types.js';

export interface ExtensionActivationResult {
  readonly isInitialized: boolean;
  readonly workspaceRoot: string;
  readonly bridge: ExtensionHostBridge;
  readonly controller: WebviewPanelController;
}

class VSCodeHostAdapter implements IHostAdapter {
  private pendingResolver?: (response: UserDecisionType) => void;

  setPendingResolver(resolver: (response: UserDecisionType) => void): void {
    this.pendingResolver = resolver;
  }

  async askUserConfirmation(request: PermissionRequest): Promise<UserDecisionType> {
    return new Promise(resolve => {
      this.pendingResolver = resolve;
    });
  }

  notify(level: 'info' | 'warn' | 'error', message: string): void {
    // Notifications logger
  }

  reportProgress(message: string): void {
    // Progress logger
  }
}

export function activateCodeGuardianExtension(
  vscodeApi?: any,
  context?: any,
  overrideWorkspaceRoot?: string
): ExtensionActivationResult {
  const workspaceRoot = overrideWorkspaceRoot || (vscodeApi?.workspace?.workspaceFolders?.[0]?.uri?.fsPath) || process.cwd();
  const config = createDefaultConfig(workspaceRoot);

  const gemini = new GeminiProvider();
  const claude = new ClaudeProvider();
  const openai = new OpenAIProvider();
  const ollama = new OllamaProvider();

  const registry = new ModelProviderRegistry([gemini, claude, openai, ollama]);
  const hostAdapter = new VSCodeHostAdapter();

  const orchestrator = new AgentOrchestrator(config, gemini, hostAdapter, { modelRegistry: registry });
  const bridge = new ExtensionHostBridge(orchestrator);
  const controller = new WebviewPanelController();

  if (vscodeApi && context) {
    let currentPanel: any = null;

    const openPanelCommand = vscodeApi.commands.registerCommand('codeguardian.openPanel', () => {
      if (currentPanel) {
        currentPanel.reveal(vscodeApi.ViewColumn.Two);
      } else {
        currentPanel = vscodeApi.window.createWebviewPanel(
          'codeguardian-panel',
          'CodeGuardian Security Panel',
          vscodeApi.ViewColumn.Two,
          { enableScripts: true, retainContextWhenHidden: true }
        );

        const nonce = controller.generateNonce();
        currentPanel.webview.html = getWebviewHtml(nonce);

        currentPanel.webview.onDidReceiveMessage(async (message: any) => {
          const response = await bridge.handleWebviewMessage(message);
          controller.postMessage(response);
        });

        controller.setMessageListener(msg => {
          if (currentPanel && currentPanel.webview) {
            currentPanel.webview.postMessage(msg);
          }
        });

        currentPanel.onDidDispose(() => {
          currentPanel = null;
        });
      }
    });

    const startCommand = vscodeApi.commands.registerCommand('codeguardian.start', async () => {
      vscodeApi.commands.executeCommand('codeguardian.openPanel');
    });

    const auditCommand = vscodeApi.commands.registerCommand('codeguardian.audit', async () => {
      const response = await bridge.handleWebviewMessage({ command: 'AUDIT' });
      controller.postMessage(response);
    });

    const rollbackCommand = vscodeApi.commands.registerCommand('codeguardian.rollback', async () => {
      const response = await bridge.handleWebviewMessage({ command: 'ROLLBACK', actionId: 'latest' });
      controller.postMessage(response);
    });

    const evidenceCommand = vscodeApi.commands.registerCommand('codeguardian.showEvidence', async () => {
      const response = await bridge.handleWebviewMessage({ command: 'GET_EVIDENCE' });
      controller.postMessage(response);
    });

    context.subscriptions.push(openPanelCommand, startCommand, auditCommand, rollbackCommand, evidenceCommand);
  }

  return {
    isInitialized: true,
    workspaceRoot,
    bridge,
    controller
  };
}

export function deactivateCodeGuardianExtension(): void {
  // Clean resource teardown
}
