import fs from 'fs';
import path from 'path';
import { ObservedEffects, ExpectedEffects } from './effectTypes.js';
import { CapabilityGrant } from '../../core/types.js';

export interface FirewallResult {
  readonly valid: boolean;
  readonly reason?: string;
  readonly violation?: {
    readonly type: string;
    readonly effect: any;
  };
}

export class EffectFirewall {
  /**
   * Deterministically validates observed effects against capability grants
   */
  validate(observedEffects: ObservedEffects, capability: CapabilityGrant): FirewallResult {
    try {
      const workspaceRoot = path.resolve(capability.workspaceRoot);

      // 1. Filesystem validations
      for (const fEffect of observedEffects.filesystem) {
        let canonicalTarget = path.resolve(fEffect.target);
        try {
          if (fs.existsSync(fEffect.target)) {
            canonicalTarget = fs.realpathSync(fEffect.target);
          }
        } catch {
          // Fallback to path.resolve if file was unreadable or deleted
        }

        // A. Confinement check
        if (!canonicalTarget.startsWith(workspaceRoot)) {
          return {
            valid: false,
            reason: `Target escapes workspace boundary: ${fEffect.target}`,
            violation: { type: 'SEC-001-WORKSPACE-BOUNDARY', effect: fEffect }
          };
        }

        // B. Sensitive/Critical path checks (e.g. .env, .git)
        const basename = path.basename(canonicalTarget);
        if (basename === '.env' || canonicalTarget.includes(path.sep + '.git' + path.sep)) {
          return {
            valid: false,
            reason: `Modification of critical configuration/metadata is strictly blocked: ${fEffect.target}`,
            violation: { type: 'SEC-003-CRITICAL-WRITE-PROTECTION', effect: fEffect }
          };
        }

        // C. Denied paths check
        for (const deniedPath of capability.deniedPaths) {
          const canonicalDenied = path.resolve(deniedPath);
          if (canonicalTarget.startsWith(canonicalDenied)) {
            return {
              valid: false,
              reason: `Target falls under explicitly denied path region: ${fEffect.target}`,
              violation: { type: 'SEC-002-DENIED-PATH', effect: fEffect }
            };
          }
        }

        // D. Expected/Allowed paths check
        const expected = capability.expectedEffects;
        let isAllowed = false;

        // By default, if the operation is a read (FILE_READ), check allowed read regions (usually entire workspace)
        if (fEffect.type === 'FILE_READ') {
          isAllowed = true; // Reading is generally allowed unless explicitly denied
        } else {
          // It's a mutation effect (FILE_CREATE, FILE_WRITE, FILE_DELETE, DIR_CREATE, DIR_DELETE)
          for (const allowedPath of expected.allowedPaths) {
            const canonicalAllowed = path.resolve(allowedPath);
            if (canonicalTarget.startsWith(canonicalAllowed)) {
              isAllowed = true;
              break;
            }
          }
        }

        if (!isAllowed) {
          return {
            valid: false,
            reason: `Unauthorized filesystem modification detected outside allowed capability paths: ${fEffect.target}`,
            violation: { type: 'SEC-004-UNAUTHORIZED-WRITE', effect: fEffect }
          };
        }
      }

      // 2. Network validations
      if (!capability.expectedEffects.allowNetwork && observedEffects.network.length > 0) {
        return {
          valid: false,
          reason: `Network activity detected but network capability is disabled.`,
          violation: { type: 'NET-001-UNAUTHORIZED-NETWORK', effect: observedEffects.network[0] }
        };
      }

      // 3. Process validations
      const allowedProcs = capability.expectedEffects.allowedProcesses;
      if (allowedProcs.length > 0) {
        for (const pEffect of observedEffects.processes) {
          let rawCmd = pEffect.commandLine.trim();
          let execToken = '';
          if (rawCmd.startsWith('"')) {
            const endQuote = rawCmd.indexOf('"', 1);
            execToken = endQuote > 0 ? rawCmd.substring(1, endQuote) : rawCmd.replace(/"/g, '');
          } else {
            execToken = rawCmd.split(' ')[0];
          }

          const procBasename = path.basename(execToken).replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();
          const isProcAllowed = allowedProcs.some((allowed: string) => {
            const allowedBasename = path.basename(allowed).replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();
            return allowedBasename === procBasename;
          });

          if (!isProcAllowed) {
            return {
              valid: false,
              reason: `Spawned process executable "${procBasename}" is not allowed by capability: ${pEffect.commandLine}`,
              violation: { type: 'EXEC-001-UNAUTHORIZED-PROCESS', effect: pEffect }
            };
          }
        }
      }

      return { valid: true };
    } catch (err: any) {
      // Fail-closed
      return {
        valid: false,
        reason: `Firewall validation error: ${err.message}`
      };
    }
  }
}
