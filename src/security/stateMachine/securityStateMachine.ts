export type SecurityState =
  | 'PROPOSED'
  | 'PARSED'
  | 'POLICY_CHECKED'
  | 'CAPABILITY_GRANTED'
  | 'ISOLATION_PREPARED'
  | 'ISOLATION_VERIFIED'
  | 'PROCESS_STARTED'
  | 'PROCESS_RUNNING'
  | 'PROCESS_TERMINATED'
  | 'EFFECTS_VERIFIED'
  | 'COMPLETED'
  | 'VIOLATED'
  | 'ROLLED_BACK';

export interface StateTransitionRecord {
  readonly fromState: SecurityState;
  readonly toState: SecurityState;
  readonly timestamp: number;
  readonly reason?: string;
}

export class SecurityStateError extends Error {
  readonly fromState: SecurityState;
  readonly toState: SecurityState;

  constructor(fromState: SecurityState, toState: SecurityState, message?: string) {
    const defaultMsg = `Illegal security state transition from "${fromState}" to "${toState}". Operation strictly blocked.`;
    super(message || defaultMsg);
    this.name = 'SecurityStateError';
    this.fromState = fromState;
    this.toState = toState;
  }
}

export class SecurityStateMachine {
  private currentState: SecurityState;
  private readonly transitions: StateTransitionRecord[] = [];

  private static readonly VALID_TRANSITIONS: Record<SecurityState, readonly SecurityState[]> = {
    PROPOSED: ['PARSED', 'VIOLATED'],
    PARSED: ['POLICY_CHECKED', 'VIOLATED'],
    POLICY_CHECKED: ['CAPABILITY_GRANTED', 'COMPLETED', 'VIOLATED'],
    CAPABILITY_GRANTED: ['ISOLATION_PREPARED', 'VIOLATED'],
    ISOLATION_PREPARED: ['ISOLATION_VERIFIED', 'VIOLATED'],
    ISOLATION_VERIFIED: ['PROCESS_STARTED', 'VIOLATED'],
    PROCESS_STARTED: ['PROCESS_RUNNING', 'VIOLATED'],
    PROCESS_RUNNING: ['PROCESS_TERMINATED', 'VIOLATED'],
    PROCESS_TERMINATED: ['EFFECTS_VERIFIED', 'VIOLATED'],
    EFFECTS_VERIFIED: ['COMPLETED', 'VIOLATED'],
    COMPLETED: [],
    VIOLATED: ['ROLLED_BACK'],
    ROLLED_BACK: []
  };

  constructor(initialState: SecurityState = 'PROPOSED') {
    this.currentState = initialState;
  }

  getCurrentState(): SecurityState {
    return this.currentState;
  }

  getTransitionHistory(): readonly StateTransitionRecord[] {
    return this.transitions;
  }

  /**
   * Deterministically attempts a security state transition.
   * Fails closed by throwing a SecurityStateError on invalid transitions.
   */
  transitionTo(nextState: SecurityState, reason?: string): SecurityState {
    const allowedNext = SecurityStateMachine.VALID_TRANSITIONS[this.currentState] || [];

    if (!allowedNext.includes(nextState)) {
      throw new SecurityStateError(this.currentState, nextState, reason);
    }

    const record: StateTransitionRecord = {
      fromState: this.currentState,
      toState: nextState,
      timestamp: Date.now(),
      reason
    };

    this.transitions.push(record);
    this.currentState = nextState;
    return this.currentState;
  }
}
