import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NetworkPolicyValidator } from '../../../../src/security/isolation/networkPolicy.js';
import { NetworkPolicy } from '../../../../src/security/isolation/isolationTypes.js';
import { NetworkEffect } from '../../../../src/security/effects/effectTypes.js';

describe('NetworkPolicy Unit Tests', () => {
  const validator = new NetworkPolicyValidator();

  it('allows zero network effects under mode: NONE', () => {
    const policy: NetworkPolicy = { mode: 'NONE' };
    const res = validator.validate(policy, []);
    assert.equal(res.valid, true);
  });

  it('rejects network activity under mode: NONE', () => {
    const policy: NetworkPolicy = { mode: 'NONE' };
    const observed: NetworkEffect[] = [
      {
        type: 'NET_CONNECT',
        target: 'api.example.com:443',
        timestamp: Date.now(),
        host: 'api.example.com',
        port: 443,
        protocol: 'TCP'
      }
    ];

    const res = validator.validate(policy, observed);
    assert.equal(res.valid, false);
    assert.equal(res.reason?.includes('strictly denied'), true);
  });

  it('allows network targets matching allowlist in mode: ALLOWLIST', () => {
    const policy: NetworkPolicy = {
      mode: 'ALLOWLIST',
      allowedHosts: ['api.github.com'],
      allowedPorts: [443]
    };
    const observed: NetworkEffect[] = [
      {
        type: 'NET_CONNECT',
        target: 'api.github.com:443',
        timestamp: Date.now(),
        host: 'api.github.com',
        port: 443,
        protocol: 'TCP'
      }
    ];

    const res = validator.validate(policy, observed);
    assert.equal(res.valid, true);
  });

  it('rejects network targets outside allowlist in mode: ALLOWLIST', () => {
    const policy: NetworkPolicy = {
      mode: 'ALLOWLIST',
      allowedHosts: ['api.github.com'],
      allowedPorts: [443]
    };
    const observed: NetworkEffect[] = [
      {
        type: 'NET_CONNECT',
        target: 'evil.com:80',
        timestamp: Date.now(),
        host: 'evil.com',
        port: 80,
        protocol: 'TCP'
      }
    ];

    const res = validator.validate(policy, observed);
    assert.equal(res.valid, false);
    assert.equal(res.reason?.includes('not in the approved network allowlist'), true);
  });
});
