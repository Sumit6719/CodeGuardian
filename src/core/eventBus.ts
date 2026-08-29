import { AuditRecord, ActionProposal, RiskAssessment, PolicyDecision } from './types.js';

export type CodeGuardianEvent =
  | { type: 'PROPOSAL_RECEIVED'; proposal: ActionProposal }
  | { type: 'RISK_ASSESSED'; actionId: string; risk: RiskAssessment }
  | { type: 'POLICY_EVALUATED'; actionId: string; decision: PolicyDecision }
  | { type: 'USER_PROMPT_SHOWN'; actionId: string }
  | { type: 'ACTION_EXECUTED'; actionId: string; success: boolean }
  | { type: 'AUDIT_RECORD_WRITTEN'; record: AuditRecord }
  | { type: 'AGENT_ITERATION'; iteration: number; totalIterations: number }
  | { type: 'PIPELINE_ERROR'; error: Error; actionId?: string };

export type EventHandler = (event: CodeGuardianEvent) => void;

export class EventBus {
  private handlers: EventHandler[] = [];

  subscribe(handler: EventHandler): () => void {
    this.handlers.push(handler);
    return () => {
      this.handlers = this.handlers.filter(h => h !== handler);
    };
  }

  emit(event: CodeGuardianEvent): void {
    for (const handler of this.handlers) {
      try {
        handler(event);
      } catch (err) {
        console.error('[EventBus] Error in event handler:', err);
      }
    }
  }
}

export const globalEventBus = new EventBus();
