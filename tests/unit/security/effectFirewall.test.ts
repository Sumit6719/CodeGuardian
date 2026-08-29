import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EffectFirewall } from '../../../src/security/effects/effectFirewall.js';
import { ObservedEffects } from '../../../src/security/effects/effectTypes.js';
import { CapabilityGrant } from '../../../src/core/types.js';

describe('EffectFirewall Unit Tests', () => {
  const workspaceRoot = '/test/workspace';
  const firewall = new EffectFirewall();

  const baseCapability: CapabilityGrant = {
    id: 'cap_test',
    operation: 'EXECUTE',
    workspaceRoot,
    allowedPaths: [workspaceRoot],
    deniedPaths: [`${workspaceRoot}/denied`],
    network: 'NONE',
    processExecution: true,
    maxExecutionTimeMs: 10000,
    maxOutputBytes: 10000,
    grantedAt: Date.now(),
    expiresAt: Date.now() + 100000,
    expectedEffects: {
      allowedPaths: [`${workspaceRoot}/src`, `${workspaceRoot}/tmp`],
      deniedPaths: [`${workspaceRoot}/denied`],
      allowNetwork: false,
      allowedProcesses: ['node', 'git']
    }
  };

  it('allows writes inside allowedPaths regions', () => {
    const observed: ObservedEffects = {
      filesystem: [
        {
          type: 'FILE_CREATE',
          target: `${workspaceRoot}/src/index.ts`,
          timestamp: Date.now()
        }
      ],
      network: [],
      processes: []
    };

    const res = firewall.validate(observed, baseCapability);
    assert.equal(res.valid, true);
  });

  it('blocks writes outside allowedPaths regions', () => {
    const observed: ObservedEffects = {
      filesystem: [
        {
          type: 'FILE_WRITE',
          target: `${workspaceRoot}/package.json`, // not under allowedPaths
          timestamp: Date.now()
        }
      ],
      network: [],
      processes: []
    };

    const res = firewall.validate(observed, baseCapability);
    assert.equal(res.valid, false);
    assert.equal(res.violation?.type, 'SEC-004-UNAUTHORIZED-WRITE');
  });

  it('blocks writes targeting sensitive files (e.g. .env)', () => {
    const observed: ObservedEffects = {
      filesystem: [
        {
          type: 'FILE_WRITE',
          target: `${workspaceRoot}/src/.env`,
          timestamp: Date.now()
        }
      ],
      network: [],
      processes: []
    };

    const res = firewall.validate(observed, baseCapability);
    assert.equal(res.valid, false);
    assert.equal(res.violation?.type, 'SEC-003-CRITICAL-WRITE-PROTECTION');
  });

  it('blocks writes falling under explicitly denied paths', () => {
    const observed: ObservedEffects = {
      filesystem: [
        {
          type: 'FILE_CREATE',
          target: `${workspaceRoot}/denied/exploit.js`,
          timestamp: Date.now()
        }
      ],
      network: [],
      processes: []
    };

    const res = firewall.validate(observed, baseCapability);
    assert.equal(res.valid, false);
    assert.equal(res.violation?.type, 'SEC-002-DENIED-PATH');
  });

  it('blocks network connections if allowNetwork capability is false', () => {
    const observed: ObservedEffects = {
      filesystem: [],
      network: [
        {
          type: 'NET_CONNECT',
          target: 'evil.com:80',
          timestamp: Date.now(),
          host: 'evil.com',
          port: 80,
          protocol: 'TCP'
        }
      ],
      processes: []
    };

    const res = firewall.validate(observed, baseCapability);
    assert.equal(res.valid, false);
    assert.equal(res.violation?.type, 'NET-001-UNAUTHORIZED-NETWORK');
  });

  it('blocks processes not in allowlisted allowedProcesses list', () => {
    const observed: ObservedEffects = {
      filesystem: [],
      network: [],
      processes: [
        {
          type: 'PROCESS_SPAWN',
          target: 'unauthorized_cmd',
          timestamp: Date.now(),
          pid: 1234,
          commandLine: 'unauthorized_cmd --exploit'
        }
      ]
    };

    const res = firewall.validate(observed, baseCapability);
    assert.equal(res.valid, false);
    assert.equal(res.violation?.type, 'EXEC-001-UNAUTHORIZED-PROCESS');
  });

  it('correctly handles quoted executable paths in process validation', () => {
    const observed: ObservedEffects = {
      filesystem: [],
      network: [],
      processes: [
        {
          type: 'PROCESS_SPAWN',
          target: 'node',
          timestamp: Date.now(),
          pid: 5678,
          commandLine: '"C:\\Program Files\\nodejs\\node.exe" script.js'
        }
      ]
    };

    const res = firewall.validate(observed, baseCapability);
    assert.equal(res.valid, true);
  });
});
