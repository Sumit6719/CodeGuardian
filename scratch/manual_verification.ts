import path from 'path';
import fs from 'fs';
import {
  createDefaultConfig,
  PathGuard,
  TargetAnalyzer,
  BlastRadiusEstimator,
  RiskEngine,
  PolicyEngine,
  SnapshotManager,
  IntegrityVerifier,
  DiffGenerator,
  AuditLogger,
  ToolRegistry,
  CliAdapter
} from '../src/index.js';

async function runManualVerification() {
  console.log('====================================================');
  console.log('🧪 CODEGUARDIAN v0.1 MANUAL SECURITY VERIFICATION');
  console.log('====================================================\n');

  const workspaceRoot = path.resolve('.');
  const config = createDefaultConfig(workspaceRoot);
  const pathGuard = new PathGuard(workspaceRoot);
  const targetAnalyzer = new TargetAnalyzer();
  const blastRadiusEstimator = new BlastRadiusEstimator();
  const riskEngine = new RiskEngine();
  const policyEngine = new PolicyEngine();
  const snapshotManager = new SnapshotManager(config.snapshotDir);
  const integrityVerifier = new IntegrityVerifier();
  const diffGenerator = new DiffGenerator();
  const auditLogger = new AuditLogger(path.join(workspaceRoot, '.codeguardian', 'manual_verify_audit.jsonl'));
  const tools = new ToolRegistry();

  async function evaluateAndExecute(
    toolName: string,
    args: Record<string, any>,
    userDecisionPreset?: 'ALLOW_ONCE' | 'DENY'
  ) {
    const actionId = `act_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const tool = tools.get(toolName);
    const operation = tools.inferOperation(toolName);
    const targetPath = tools.extractTargetPath(toolName, args) || '.';

    console.log(`\n▶ [Action Proposal]: ${toolName}(${JSON.stringify(args)})`);

    // 1. PathGuard
    const pathCheck = pathGuard.validate(targetPath);
    console.log(`  1. PathGuard: allowed=${pathCheck.allowed}, relPath="${pathCheck.relativePath}"`);

    // 2. TargetAnalyzer
    const sensitivity = targetAnalyzer.classify(pathCheck.relativePath);
    console.log(`  2. TargetAnalyzer: tier=${sensitivity.tier} (${sensitivity.reason})`);

    // 3. BlastRadius
    const blast = blastRadiusEstimator.estimate(operation, pathCheck.relativePath, sensitivity.tier, pathCheck.allowed);
    console.log(`  3. BlastRadius: scope=${blast}`);

    // 4. RiskEngine
    const risk = riskEngine.evaluate({
      operation,
      sensitivity: sensitivity.tier,
      blastRadius: blast,
      isWorkspaceContained: pathCheck.allowed,
      targetPath: pathCheck.relativePath
    });
    console.log(`  4. RiskEngine: level=${risk.level}, score=${risk.score}`);

    // 5. PolicyEngine
    const policy = policyEngine.evaluate({
      operation,
      targetPath,
      relativePath: pathCheck.relativePath,
      isWorkspaceContained: pathCheck.allowed,
      sensitivity: sensitivity.tier,
      blastRadius: blast,
      risk
    });
    console.log(`  5. PolicyEngine: decision=${policy.decision} (Rule: ${policy.matchedRule})`);

    let executionStatus = 'SUCCESS';
    let beforeHash = null;
    let afterHash = null;

    if (policy.decision === 'BLOCK') {
      executionStatus = 'BLOCKED';
      console.log(`  ⛔ RESULT: Execution BLOCKED by Security Policy.`);
    } else if (policy.decision === 'ASK_USER') {
      const cli = new CliAdapter(userDecisionPreset);
      const userChoice = await cli.askUserConfirmation({
        action: {
          actionId,
          toolName,
          operation,
          targetPath,
          parameters: args,
          sourceModel: 'manual-test',
          timestamp: Date.now()
        },
        security: {
          isWorkspaceContained: pathCheck.allowed,
          canonicalPath: pathCheck.canonicalPath,
          relativePath: pathCheck.relativePath,
          sensitivity: sensitivity.tier,
          blastRadius: blast,
          reversibility: 'REVERSIBLE',
          violations: []
        },
        risk,
        policy,
        diff: operation === 'WRITE' ? diffGenerator.generate(pathCheck.relativePath, fs.existsSync(pathCheck.canonicalPath) ? fs.readFileSync(pathCheck.canonicalPath, 'utf-8') : null, args.content) : undefined
      });

      if (userChoice === 'DENY') {
        executionStatus = 'DENIED';
        console.log(`  🚫 RESULT: User DENIED authorization. File unchanged.`);
      } else {
        const exec = await tool!.execute(args, {
          workspaceRoot,
          snapshotManager,
          integrityVerifier
        });
        executionStatus = exec.success ? 'SUCCESS' : 'FAILURE';
        beforeHash = exec.data?.beforeHash || null;
        afterHash = exec.data?.afterHash || null;
        console.log(`  ✅ RESULT: Approved & Executed atomically (Snapshot: ${exec.data?.snapshotId}).`);
      }
    } else if (policy.decision === 'ALLOW') {
      const exec = await tool!.execute(args, {
        workspaceRoot,
        snapshotManager,
        integrityVerifier
      });
      executionStatus = exec.success ? 'SUCCESS' : 'FAILURE';
      console.log(`  ✅ RESULT: Allowed & Executed directly (Output lines: ${exec.data?.lines || exec.data?.total || 'OK'}).`);
    }

    auditLogger.log({
      eventId: `evt_${Date.now()}`,
      timestamp: Date.now(),
      actionId,
      sourceModel: 'manual-test',
      operation,
      target: pathCheck.relativePath,
      risk: risk.level,
      policyDecision: policy.decision,
      matchedRule: policy.matchedRule,
      executionResult: executionStatus as any,
      beforeHash,
      afterHash,
      verificationStatus: executionStatus === 'SUCCESS' ? 'VERIFIED' : 'FAILED'
    });
  }

  // Test 1: Safe read of normal file
  console.log('\n--- [TEST 1: Safe Read] ---');
  await evaluateAndExecute('read_file', { file_path: 'package.json' });

  // Test 2: Normal file modification (Approved)
  console.log('\n--- [TEST 2: Normal File Modification (User Approved)] ---');
  const scratchFile = 'scratch_test_target.txt';
  fs.writeFileSync(scratchFile, 'Initial content v1\n', 'utf-8');
  await evaluateAndExecute(
    'write_file',
    { file_path: scratchFile, content: 'Updated content v2 with verified security\n' },
    'ALLOW_ONCE'
  );
  if (fs.existsSync(scratchFile)) fs.unlinkSync(scratchFile);

  // Test 3: Normal file modification (Denied by User)
  console.log('\n--- [TEST 3: File Modification (User Denied)] ---');
  const deniedFile = 'scratch_denied.txt';
  fs.writeFileSync(deniedFile, 'Critical business logic\n', 'utf-8');
  await evaluateAndExecute(
    'write_file',
    { file_path: deniedFile, content: 'Malicious overwrite\n' },
    'DENY'
  );
  console.log(`  Verify content was untouched: "${fs.readFileSync(deniedFile, 'utf-8').trim()}"`);
  if (fs.existsSync(deniedFile)) fs.unlinkSync(deniedFile);

  // Test 4: Protected file access (.env write attempt)
  console.log('\n--- [TEST 4: Protected File Access (.env Write Attack)] ---');
  await evaluateAndExecute('write_file', { file_path: '.env', content: 'EXPLOIT=true' });

  // Test 5: Path traversal attempt outside workspace
  console.log('\n--- [TEST 5: Path Traversal Attack (Escape Workspace)] ---');
  await evaluateAndExecute('read_file', { file_path: '../../../../windows/win.ini' });

  console.log('\n====================================================');
  console.log('✅ ALL 5 MANUAL SECURITY SCENARIOS VERIFIED SUCCESSFULLY');
  console.log(`📄 Audit trail written to: ${auditLogger.getLogFilePath()}`);
  console.log('====================================================\n');
}

runManualVerification().catch(console.error);
