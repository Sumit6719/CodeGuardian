/**
 * Generates the functional HTML/CSS/JS layout for the CodeGuardian VS Code Webview panel.
 * Communicates strictly via acquireVsCodeApi().postMessage() through the WebviewProtocol RPC bridge.
 */
export function getWebviewHtml(nonce: string): string {
  return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CodeGuardian Security Panel</title>
  <style>
    :root {
      --bg: #1e1e2e;
      --card-bg: #282a36;
      --accent: #bd93f9;
      --success: #50fa7b;
      --warn: #ffb86c;
      --danger: #ff5555;
      --text: #f8f8f2;
      --subtext: #6272a4;
      --border: #44475a;
    }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      padding: 16px;
      margin: 0;
      font-size: 13px;
      line-height: 1.4;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      padding-bottom: 12px;
      margin-bottom: 16px;
    }
    .header h2 {
      margin: 0;
      color: var(--accent);
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 16px;
    }
    .badge {
      background: var(--border);
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 16px;
    }
    .card h3 {
      margin-top: 0;
      margin-bottom: 10px;
      font-size: 13px;
      color: var(--accent);
      border-bottom: 1px solid rgba(255,255,255,0.05);
      padding-bottom: 6px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 10px;
    }
    .stat-box {
      background: rgba(0,0,0,0.2);
      padding: 8px 10px;
      border-radius: 6px;
      border-left: 3px solid var(--accent);
    }
    .stat-box.success { border-left-color: var(--success); }
    .stat-box.warn { border-left-color: var(--warn); }
    .stat-box.danger { border-left-color: var(--danger); }
    .stat-label { font-size: 10px; color: var(--subtext); text-transform: uppercase; }
    .stat-val { font-size: 12px; font-weight: bold; margin-top: 2px; }
    textarea {
      width: 100%;
      height: 70px;
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 6px;
      padding: 8px;
      font-family: inherit;
      resize: vertical;
      box-sizing: border-box;
    }
    .btn-group {
      display: flex;
      gap: 8px;
      margin-top: 10px;
    }
    button {
      background: var(--accent);
      color: #1e1e2e;
      border: none;
      padding: 8px 14px;
      border-radius: 6px;
      font-weight: bold;
      cursor: pointer;
      font-size: 12px;
      transition: opacity 0.2s;
    }
    button:hover { opacity: 0.9; }
    button.btn-danger { background: var(--danger); color: #fff; }
    button.btn-success { background: var(--success); color: #1e1e2e; }
    button.btn-secondary { background: var(--border); color: var(--text); }
    .diff-box {
      background: rgba(0,0,0,0.4);
      font-family: monospace;
      padding: 10px;
      border-radius: 6px;
      max-height: 150px;
      overflow-y: auto;
      white-space: pre-wrap;
      font-size: 11px;
    }
    .diff-add { color: var(--success); }
    .diff-del { color: var(--danger); }
    .hidden { display: none !important; }
    .log-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
    }
    .log-table th, .log-table td {
      text-align: left;
      padding: 6px 8px;
      border-bottom: 1px solid var(--border);
    }
    .log-table th { color: var(--subtext); }
  </style>
</head>
<body>
  <div class="header">
    <h2>🛡️ CodeGuardian <span class="badge">v0.6.0</span></h2>
    <div id="statusBadge" class="badge" style="background: var(--success); color: #1e1e2e;">IDLE</div>
  </div>

  <!-- A. REQUEST INPUT -->
  <div class="card">
    <h3>📝 Request Proposal</h3>
    <textarea id="promptInput" placeholder="Describe the feature or fix you want CodeGuardian to implement..."></textarea>
    <div class="btn-group">
      <button id="btnSubmit" onclick="submitProposal()">Execute Request</button>
      <button class="btn-secondary" onclick="fetchEvidence()">Refresh Evidence</button>
    </div>
  </div>

  <!-- B & C. SECURITY DASHBOARD & MULTI-MODEL STATE -->
  <div class="card">
    <h3>🔒 Security & Multi-Model Engine</h3>
    <div class="grid">
      <div class="stat-box success">
        <div class="stat-label">Isolation Level</div>
        <div id="valIsolation" class="stat-val">PROCESS</div>
      </div>
      <div class="stat-box success">
        <div class="stat-label">Network Policy</div>
        <div id="valNetwork" class="stat-val">NONE</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Active Provider</div>
        <div id="valProvider" class="stat-val">Gemini 2.5</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Model Consensus</div>
        <div id="valConsensus" class="stat-val">AGREED (0.0)</div>
      </div>
    </div>
  </div>

  <!-- D & E. PROPOSAL CARD & DIFF VIEWER -->
  <div id="proposalCard" class="card hidden">
    <h3>⚠️ Governed Action Proposal</h3>
    <div class="grid" style="margin-bottom: 10px;">
      <div class="stat-box warn">
        <div class="stat-label">Operation</div>
        <div id="propOp" class="stat-val">WRITE</div>
      </div>
      <div class="stat-box warn">
        <div class="stat-label">Target File</div>
        <div id="propTarget" class="stat-val">src/app.ts</div>
      </div>
      <div class="stat-box warn">
        <div class="stat-label">Risk Level</div>
        <div id="propRisk" class="stat-val">MEDIUM (35)</div>
      </div>
    </div>
    <div class="stat-label" style="margin-bottom: 4px;">Proposed Diff Preview:</div>
    <div id="diffBox" class="diff-box">No diff content.</div>

    <!-- F. APPROVAL CONTROLS -->
    <div id="approvalGroup" class="btn-group hidden">
      <button class="btn-success" onclick="sendApproval('ALLOW')">Approve & Execute</button>
      <button class="btn-danger" onclick="sendApproval('DENY')">Reject Action</button>
    </div>
  </div>

  <!-- G & H. LIFECYCLE & REGRESSION VERIFICATION -->
  <div class="card">
    <h3>🔍 Execution & Verification State</h3>
    <div class="stat-label">Current Pipeline State:</div>
    <div id="lifecycleState" class="stat-val" style="color: var(--accent); margin-bottom: 8px;">PROPOSED</div>
    <div class="grid">
      <div class="stat-box">
        <div class="stat-label">Effect Firewall</div>
        <div id="valFirewall" class="stat-val">VALIDATED</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Regression Guard</div>
        <div id="valRegression" class="stat-val">PASSED</div>
      </div>
    </div>
  </div>

  <!-- I. ROLLBACK CONTROL -->
  <div class="card">
    <h3>⏪ Atomic Rollback & State Restoration</h3>
    <div class="btn-group">
      <button class="btn-danger" onclick="triggerRollback()">Rollback Latest Modification</button>
    </div>
    <div id="rollbackStatus" class="stat-val" style="margin-top: 6px; font-size: 11px; color: var(--subtext);">No rollback performed.</div>
  </div>

  <!-- J. CRYPTOGRAPHIC EVIDENCE LEDGER -->
  <div class="card">
    <h3>🔗 Cryptographic Evidence Chain</h3>
    <div style="margin-bottom: 8px; font-size: 11px;">
      Ledger Integrity: <strong id="valLedgerValid" style="color: var(--success);">VALID (SHA-256 Chained)</strong>
    </div>
    <table class="log-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Event</th>
          <th>Target</th>
          <th>Decision</th>
        </tr>
      </thead>
      <tbody id="evidenceTable">
        <tr><td colspan="4" style="color: var(--subtext);">No evidence records loaded.</td></tr>
      </tbody>
    </table>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();

    function submitProposal() {
      const text = document.getElementById('promptInput').value;
      if (!text) return;
      document.getElementById('statusBadge').innerText = 'RUNNING';
      vscode.postMessage({ command: 'SUBMIT_PROPOSAL', goal: text });
    }

    function sendApproval(decision) {
      document.getElementById('approvalGroup').classList.add('hidden');
      if (decision === 'ALLOW') {
        vscode.postMessage({ command: 'APPROVE', decision: 'ALLOW' });
      } else {
        vscode.postMessage({ command: 'REJECT', decision: 'DENY' });
      }
    }

    function triggerRollback() {
      vscode.postMessage({ command: 'ROLLBACK', actionId: 'latest' });
    }

    function fetchEvidence() {
      vscode.postMessage({ command: 'GET_EVIDENCE' });
    }

    window.addEventListener('message', event => {
      const msg = event.data;
      if (!msg) return;

      if (msg.type === 'STATE_UPDATE' && msg.payload) {
        document.getElementById('statusBadge').innerText = 'COMPLETED';
        if (msg.payload.summary) {
          document.getElementById('lifecycleState').innerText = 'COMPLETED';
        }
      } else if (msg.type === 'PERMISSION_REQUEST') {
        document.getElementById('proposalCard').classList.remove('hidden');
        document.getElementById('approvalGroup').classList.remove('hidden');
        document.getElementById('propOp').innerText = msg.payload.operation || 'WRITE';
        document.getElementById('propTarget').innerText = msg.payload.target || 'src/app.ts';
        document.getElementById('propRisk').innerText = (msg.payload.riskLevel || 'HIGH');
        document.getElementById('diffBox').innerText = msg.payload.diffText || 'No diff available.';
      } else if (msg.type === 'EVIDENCE_DATA' && msg.payload) {
        document.getElementById('valLedgerValid').innerText = msg.payload.isIntegrityValid ? 'VALID (SHA-256 Chained)' : 'TAMPERED';
        const tbody = document.getElementById('evidenceTable');
        if (msg.payload.records && msg.payload.records.length > 0) {
          tbody.innerHTML = msg.payload.records.map(r => \`
            <tr>
              <td>\${new Date(r.timestamp).toLocaleTimeString()}</td>
              <td>\${r.event}</td>
              <td>\${r.data.target || '-'}</td>
              <td>\${r.data.decision || 'ALLOW'}</td>
            </tr>
          \`).join('');
        }
      }
    });
  </script>
</body>
</html>`;
}
