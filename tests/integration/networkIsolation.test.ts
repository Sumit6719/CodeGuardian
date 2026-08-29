import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NetworkPolicyValidator } from '../../src/security/isolation/networkPolicy.js';
import { NetworkPolicy } from '../../src/security/isolation/isolationTypes.js';
import { NetworkEffect } from '../../src/security/effects/effectTypes.js';

describe('NetworkIsolation Integration Tests', () => {
  const validator = new NetworkPolicyValidator();

  it('enforces network policy mode NONE on observed network side effects', () => {
    const policy: NetworkPolicy = { mode: 'NONE' };
    const observedEffects: NetworkEffect[] = [
      {
        type: 'NET_CONNECT',
        target: 'http://malicious.org:80',
        timestamp: Date.now(),
        host: 'malicious.org',
        port: 80,
        protocol: 'TCP'
      }
    ];

    const result = validator.validate(policy, observedEffects);
    assert.equal(result.valid, false);
    assert.equal(result.violation?.host, 'malicious.org');
  });

  it('allows approved host and port targets under mode ALLOWLIST', () => {
    const policy: NetworkPolicy = {
      mode: 'ALLOWLIST',
      allowedHosts: ['registry.npmjs.org'],
      allowedPorts: [443]
    };
    const observedEffects: NetworkEffect[] = [
      {
        type: 'NET_CONNECT',
        target: 'registry.npmjs.org:443',
        timestamp: Date.now(),
        host: 'registry.npmjs.org',
        port: 443,
        protocol: 'TCP'
      }
    ];

    const result = validator.validate(policy, observedEffects);
    assert.equal(result.valid, true);
  });
});
