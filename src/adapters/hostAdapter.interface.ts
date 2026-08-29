import { PermissionRequest, UserDecisionType } from '../core/types.js';

export interface IHostAdapter {
  /**
   * Prompts the user to authorize or deny an action proposal.
   */
  askUserConfirmation(request: PermissionRequest): Promise<UserDecisionType>;

  /**
   * Sends notifications to the host interface
   */
  notify(level: 'info' | 'warn' | 'error', message: string): void;

  /**
   * Reports task or iteration progress
   */
  reportProgress(message: string): void;
}
