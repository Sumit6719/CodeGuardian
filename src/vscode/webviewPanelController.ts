import { ExtensionResponsePayload } from './webviewProtocol.js';

export interface WebviewPanelState {
  readonly activeGoal?: string;
  readonly status: 'IDLE' | 'RUNNING' | 'WAITING_USER' | 'COMPLETED' | 'ERROR';
  readonly lastDiff?: string;
  readonly riskLevel?: string;
  readonly evidenceChainLength?: number;
}

export class WebviewPanelController {
  private panelState: WebviewPanelState = { status: 'IDLE' };
  private messageListener?: (msg: ExtensionResponsePayload) => void;

  setMessageListener(listener: (msg: ExtensionResponsePayload) => void): void {
    this.messageListener = listener;
  }

  getPanelState(): WebviewPanelState {
    return this.panelState;
  }

  /**
   * Posts formatted, secret-scrubbed state updates to the VS Code Webview panel.
   */
  postMessage(response: ExtensionResponsePayload): void {
    const sanitizedResponse = this.sanitizeSecrets(response);
    if (this.messageListener) {
      this.messageListener(sanitizedResponse);
    }
  }

  updateState(status: WebviewPanelState['status'], goal?: string, riskLevel?: string): void {
    this.panelState = {
      ...this.panelState,
      status,
      activeGoal: goal || this.panelState.activeGoal,
      riskLevel: riskLevel || this.panelState.riskLevel
    };
    this.postMessage({
      type: 'STATE_UPDATE',
      success: true,
      payload: this.panelState
    });
  }

  private sanitizeSecrets(data: any): any {
    if (!data) return data;
    const jsonStr = JSON.stringify(data);
    const scrubbedStr = jsonStr.replace(/(?:sk-ant-|sk-|GEMINI_KEY|apiKey=)[a-zA-Z0-9_\-\.]{15,}/g, '[REDACTED_SECRET]');
    return JSON.parse(scrubbedStr);
  }
}
