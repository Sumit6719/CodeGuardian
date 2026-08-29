import { NetworkPolicy } from './isolationTypes.js';
import { NetworkEffect } from '../effects/effectTypes.js';

export interface NetworkValidationResult {
  readonly valid: boolean;
  readonly reason?: string;
  readonly violation?: NetworkEffect;
}

export class NetworkPolicyValidator {
  /**
   * Validates observed network effects against an enforced NetworkPolicy
   */
  validate(policy: NetworkPolicy, observedNetwork: readonly NetworkEffect[]): NetworkValidationResult {
    if (observedNetwork.length === 0) {
      return { valid: true };
    }

    if (policy.mode === 'NONE') {
      return {
        valid: false,
        reason: 'Network activity is strictly denied by NetworkPolicy (mode: NONE).',
        violation: observedNetwork[0]
      };
    }

    if (policy.mode === 'ALLOWLIST') {
      const allowedHosts = new Set((policy.allowedHosts || []).map(h => h.toLowerCase()));
      const allowedPorts = new Set(policy.allowedPorts || []);

      for (const effect of observedNetwork) {
        const hostMatch = allowedHosts.has(effect.host.toLowerCase()) || allowedHosts.has('*');
        const portMatch = allowedPorts.size === 0 || allowedPorts.has(effect.port);

        if (!hostMatch || !portMatch) {
          return {
            valid: false,
            reason: `Network target ${effect.host}:${effect.port} is not in the approved network allowlist.`,
            violation: effect
          };
        }
      }
    }

    return { valid: true };
  }
}
