import { AgentOrchestrator, OrchestrationResult } from '../agent/orchestrator.js';
import { validateWebviewMessage, ExtensionResponsePayload, WebviewProtocolError } from './webviewProtocol.js';

export class ExtensionHostBridge {
  private readonly orchestrator: AgentOrchestrator;

  constructor(orchestrator: AgentOrchestrator) {
    this.orchestrator = orchestrator;
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

        case 'SUBMIT_PROPOSAL': {
          if (!validated.goal) {
            throw new WebviewProtocolError('Goal prompt is required for SUBMIT_PROPOSAL command.');
          }
          const result: OrchestrationResult = await this.orchestrator.run(validated.goal);
          return { type: 'STATE_UPDATE', success: true, payload: result };
        }

        case 'TRIGGER_ROLLBACK': {
          if (!validated.actionId) {
            throw new WebviewProtocolError('actionId is required for TRIGGER_ROLLBACK command.');
          }
          const rollbackManager = this.orchestrator.getRollbackManager();
          const result = rollbackManager.rollback(validated.actionId);
          return { type: 'STATE_UPDATE', success: result.success, payload: result };
        }

        case 'REQUEST_AUDIT_LOG': {
          const ledger = this.orchestrator.getEvidenceLedger();
          const records = ledger.readAll();
          return { type: 'AUDIT_DATA', success: true, payload: { recordsCount: records.length, isIntegrityValid: ledger.verifyLedgerIntegrity().valid } };
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
