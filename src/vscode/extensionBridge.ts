import { AgentOrchestrator, OrchestrationResult } from '../agent/orchestrator.js';
import { validateWebviewMessage, ExtensionResponsePayload, WebviewProtocolError } from './webviewProtocol.js';

export class ExtensionHostBridge {
  private readonly orchestrator: AgentOrchestrator;
  private pendingUserResolver?: (decision: 'ALLOW' | 'DENY') => void;

  constructor(orchestrator: AgentOrchestrator) {
    this.orchestrator = orchestrator;
  }

  /**
   * Registers a resolver callback for explicit ASK_USER confirmation prompts.
   */
  setPendingUserResolver(resolver: (decision: 'ALLOW' | 'DENY') => void): void {
    this.pendingUserResolver = resolver;
  }

  /**
   * Translates incoming validated VS Code requests directly into calls to the governed AgentOrchestrator.
   * Every execution path uses the full CodeGuardian security pipeline.
   */
  async handleWebviewMessage(rawMessage: any): Promise<ExtensionResponsePayload> {
    try {
      const validated = validateWebviewMessage(rawMessage);

      switch (validated.command) {
        case 'PING':
          return { type: 'PONG', success: true, payload: { timestamp: Date.now() } };

        case 'START':
        case 'SUBMIT_PROPOSAL': {
          if (!validated.goal) {
            throw new WebviewProtocolError('Goal prompt is required for proposal execution.');
          }
          const result: OrchestrationResult = await this.orchestrator.run(validated.goal);
          return { type: 'STATE_UPDATE', success: true, payload: result };
        }

        case 'APPROVE':
        case 'APPROVE_ACTION': {
          if (this.pendingUserResolver) {
            this.pendingUserResolver('ALLOW');
            this.pendingUserResolver = undefined;
          }
          return { type: 'STATE_UPDATE', success: true, payload: { decision: 'ALLOW' } };
        }

        case 'REJECT':
        case 'DENY_ACTION': {
          if (this.pendingUserResolver) {
            this.pendingUserResolver('DENY');
            this.pendingUserResolver = undefined;
          }
          return { type: 'STATE_UPDATE', success: true, payload: { decision: 'DENY' } };
        }

        case 'ROLLBACK':
        case 'TRIGGER_ROLLBACK': {
          const actionId = validated.actionId || 'latest';
          const rollbackManager = this.orchestrator.getRollbackManager();
          const result = rollbackManager.rollback(actionId);
          return { type: 'STATE_UPDATE', success: result.success, payload: result };
        }

        case 'REQUEST_AUDIT_LOG': {
          const ledger = this.orchestrator.getEvidenceLedger();
          const records = ledger.readAll();
          const integrity = ledger.verifyLedgerIntegrity();
          return {
            type: 'AUDIT_DATA',
            success: true,
            payload: {
              recordsCount: records.length,
              isIntegrityValid: integrity.valid,
              records: records.slice(-20)
            }
          };
        }

        case 'AUDIT':
        case 'GET_EVIDENCE': {
          const ledger = this.orchestrator.getEvidenceLedger();
          const records = ledger.readAll();
          const integrity = ledger.verifyLedgerIntegrity();
          return {
            type: 'EVIDENCE_DATA',
            success: true,
            payload: {
              recordsCount: records.length,
              isIntegrityValid: integrity.valid,
              records: records.slice(-20)
            }
          };
        }

        case 'GET_STATE': {
          const ledger = this.orchestrator.getEvidenceLedger();
          return {
            type: 'STATE_UPDATE',
            success: true,
            payload: {
              workspaceRoot: this.orchestrator.getEvidenceLedger() ? 'CONFIGURED' : 'INITIALIZING',
              recordsCount: ledger.readAll().length
            }
          };
        }

        case 'SELECT_MODEL': {
          return {
            type: 'STATE_UPDATE',
            success: true,
            payload: { selectedModel: validated.modelId || 'gemini' }
          };
        }

        default:
          throw new WebviewProtocolError(`Unhandled Webview command: ${validated.command}`);
      }
    } catch (err: any) {
      return {
        type: 'ERROR',
        success: false,
        error: err.message
      };
    }
  }
}
