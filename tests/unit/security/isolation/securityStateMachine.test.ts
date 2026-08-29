import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SecurityStateMachine, SecurityStateError } from '../../../../src/security/stateMachine/securityStateMachine.js';

describe('SecurityStateMachine Unit Tests', () => {
  it('starts in initial state PROPOSED', () => {
    const sm = new SecurityStateMachine('PROPOSED');
    assert.equal(sm.getCurrentState(), 'PROPOSED');
  });

  it('allows valid state transitions in sequence', () => {
    const sm = new SecurityStateMachine('PROPOSED');

    assert.equal(sm.transitionTo('PARSED'), 'PARSED');
    assert.equal(sm.transitionTo('POLICY_CHECKED'), 'POLICY_CHECKED');
    assert.equal(sm.transitionTo('CAPABILITY_GRANTED'), 'CAPABILITY_GRANTED');
    assert.equal(sm.transitionTo('ISOLATION_PREPARED'), 'ISOLATION_PREPARED');
    assert.equal(sm.transitionTo('ISOLATION_VERIFIED'), 'ISOLATION_VERIFIED');
    assert.equal(sm.transitionTo('PROCESS_STARTED'), 'PROCESS_STARTED');
    assert.equal(sm.transitionTo('PROCESS_RUNNING'), 'PROCESS_RUNNING');
    assert.equal(sm.transitionTo('PROCESS_TERMINATED'), 'PROCESS_TERMINATED');
    assert.equal(sm.transitionTo('EFFECTS_VERIFIED'), 'EFFECTS_VERIFIED');
    assert.equal(sm.transitionTo('COMPLETED'), 'COMPLETED');
  });

  it('throws SecurityStateError and fails closed on invalid transition', () => {
    const sm = new SecurityStateMachine('PROPOSED');

    assert.throws(
      () => {
        // Attempting to jump directly from PROPOSED to PROCESS_RUNNING
        sm.transitionTo('PROCESS_RUNNING');
      },
      (err: any) => {
        return err instanceof SecurityStateError && err.fromState === 'PROPOSED' && err.toState === 'PROCESS_RUNNING';
      }
    );
  });

  it('allows transition to VIOLATED and ROLLED_BACK on failure', () => {
    const sm = new SecurityStateMachine('PROCESS_RUNNING');
    assert.equal(sm.transitionTo('VIOLATED'), 'VIOLATED');
    assert.equal(sm.transitionTo('ROLLED_BACK'), 'ROLLED_BACK');
  });

  it('records full transition history for auditing', () => {
    const sm = new SecurityStateMachine('PROPOSED');
    sm.transitionTo('PARSED', 'Parsed CLI arguments');
    sm.transitionTo('POLICY_CHECKED', 'Command policy passed');

    const history = sm.getTransitionHistory();
    assert.equal(history.length, 2);
    assert.equal(history[0].fromState, 'PROPOSED');
    assert.equal(history[0].toState, 'PARSED');
    assert.equal(history[1].fromState, 'PARSED');
    assert.equal(history[1].toState, 'POLICY_CHECKED');
  });
});
