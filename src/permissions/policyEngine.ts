import { IPolicyRule, PolicyContext } from './policy.interface.js';
import { DEFAULT_POLICY_RULES } from './defaultPolicies.js';
import { PolicyDecision } from '../core/types.js';
import { SessionStore } from './sessionStore.js';

export class PolicyEngine {
  private readonly rules: readonly IPolicyRule[];
  private readonly sessionStore: SessionStore;

  constructor(rules: readonly IPolicyRule[] = DEFAULT_POLICY_RULES, sessionStore?: SessionStore) {
    this.rules = rules;
    this.sessionStore = sessionStore || new SessionStore();
  }

  getSessionStore(): SessionStore {
    return this.sessionStore;
  }

  /**
   * Deterministically evaluates policy rules against the given context.
   */
  evaluate(context: PolicyContext): PolicyDecision {
    for (const rule of this.rules) {
      const result = rule.evaluate(context);

      if (result.applicable && result.decision) {
        // If rule suggests asking user, check if session permission was previously granted
        if (result.decision === 'ASK_USER') {
          if (this.sessionStore.isApproved(context.operation, context.relativePath)) {
            return {
              decision: 'ALLOW',
              matchedRule: `${result.ruleId || rule.id} (SESSION_APPROVED)`,
              reason: `Previously approved for this session: ${context.relativePath}`,
              requiresUserConfirmation: false
            };
          }

          return {
            decision: 'ASK_USER',
            matchedRule: result.ruleId || rule.id,
            reason: result.reason || rule.description,
            requiresUserConfirmation: true
          };
        }

        // Return decisive ALLOW or BLOCK
        return {
          decision: result.decision,
          matchedRule: result.ruleId || rule.id,
          reason: result.reason || rule.description,
          requiresUserConfirmation: false
        };
      }
    }

    // Safety fallback: if no rule matched (should not happen with default fallback rule)
    return {
      decision: 'BLOCK',
      matchedRule: 'FALLBACK_FAIL_CLOSED',
      reason: 'No policy rule permitted this action. Failing closed.',
      requiresUserConfirmation: false
    };
  }
}
