import fs from 'fs';
import path from 'path';
import { CommandParser } from './commandParser.js';
import { CommandPolicy } from './commandPolicy.js';

export interface NpmScriptAnalysisResult {
  readonly success: boolean;
  readonly chain: string[];
  readonly error?: string;
  readonly matchedRule?: string;
  readonly riskLevel?: string;
  readonly riskScore?: number;
}

export class NpmScriptAnalyzer {
  private readonly commandParser: CommandParser;
  private readonly commandPolicy: CommandPolicy;
  private readonly workspaceRoot: string;
  private readonly maxDepth: number;
  private readonly maxScripts: number;

  constructor(
    workspaceRoot: string,
    commandParser: CommandParser,
    commandPolicy: CommandPolicy,
    options?: { maxDepth?: number; maxScripts?: number }
  ) {
    this.workspaceRoot = workspaceRoot;
    this.commandParser = commandParser;
    this.commandPolicy = commandPolicy;
    this.maxDepth = options?.maxDepth ?? 5;
    this.maxScripts = options?.maxScripts ?? 10;
  }

  /**
   * Performs recursive analysis on npm scripts to detect cycle patterns, shell escapes, or dangerous payloads.
   */
  analyze(scriptName: string): NpmScriptAnalysisResult {
    const packageJsonPath = path.join(this.workspaceRoot, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return {
        success: false,
        chain: [scriptName],
        error: 'package.json not found in workspace root.'
      };
    }

    let scripts: Record<string, string> = {};
    try {
      const packageContent = fs.readFileSync(packageJsonPath, 'utf-8');
      const parsedJson = JSON.parse(packageContent);
      scripts = parsedJson.scripts || {};
    } catch (err: any) {
      return {
        success: false,
        chain: [scriptName],
        error: `Failed to parse package.json: ${err.message}`
      };
    }

    const visited = new Set<string>();
    const chain: string[] = [];
    let scriptsInspected = 0;
    
    // Accumulators for escalated decisions
    let worstDecision: 'ALLOW' | 'ASK_USER' | 'BLOCK' = 'ALLOW';
    let worstMatchedRule: string | undefined = undefined;
    let worstRiskLevel: string | undefined = undefined;
    let worstRiskScore: number | undefined = undefined;

    const traverse = (name: string, depth: number): { success: boolean; error?: string } => {
      if (depth > this.maxDepth) {
        return { success: false, error: `Maximum recursion depth of ${this.maxDepth} exceeded.` };
      }
      if (scriptsInspected >= this.maxScripts) {
        return { success: false, error: `Maximum scripts limit of ${this.maxScripts} exceeded.` };
      }
      if (visited.has(name)) {
        return { success: false, error: `Script dependency cycle detected: ${name}` };
      }

      visited.add(name);
      chain.push(name);
      scriptsInspected++;

      const cmdString = scripts[name];
      if (!cmdString) {
        return { success: false, error: `Script "${name}" is not defined in package.json.` };
      }

      // Parse and evaluate the script command string
      const parsedCmd = this.commandParser.parse(cmdString);
      const policyEval = this.commandPolicy.evaluate(parsedCmd);

      // If the command policy blocks, we immediately fail
      if (policyEval.decision === 'BLOCK') {
        worstDecision = 'BLOCK';
        worstMatchedRule = policyEval.matchedRule;
        worstRiskLevel = policyEval.riskLevel;
        worstRiskScore = policyEval.riskScore;
        return {
          success: false,
          error: `Blocked by rule [${policyEval.matchedRule}]: ${policyEval.reason} (inside script "${name}": "${cmdString}")`
        };
      }

      // Track escalated risk levels
      if (policyEval.decision === 'ASK_USER') {
        worstDecision = 'ASK_USER';
        worstMatchedRule = policyEval.matchedRule;
        worstRiskLevel = policyEval.riskLevel;
        worstRiskScore = policyEval.riskScore;
      }

      // Traverse into nested scripts
      const exec = parsedCmd.executable;
      const args = parsedCmd.args;

      if (['npm', 'yarn', 'pnpm'].includes(exec)) {
        let nestedScriptName = '';
        if (args[0] === 'run' && args[1]) {
          nestedScriptName = args[1];
        } else if (args[0] && args[0] !== 'run' && scripts[args[0]]) {
          nestedScriptName = args[0];
        }

        if (nestedScriptName) {
          const nestedResult = traverse(nestedScriptName, depth + 1);
          if (!nestedResult.success) {
            return nestedResult;
          }
        }
      }

      visited.delete(name);
      return { success: true };
    };

    const result = traverse(scriptName, 1);

    return {
      success: result.success,
      chain,
      error: result.error,
      matchedRule: worstMatchedRule,
      riskLevel: worstRiskLevel,
      riskScore: worstRiskScore
    };
  }
}
