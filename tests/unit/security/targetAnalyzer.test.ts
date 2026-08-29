import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { TargetAnalyzer } from '../../../src/security/targetAnalyzer.js';

describe('TargetAnalyzer Sensitivity Classification', () => {
  const analyzer = new TargetAnalyzer();

  it('classifies .env files as CRITICAL', () => {
    assert.equal(analyzer.classify('.env').tier, 'CRITICAL');
    assert.equal(analyzer.classify('.env.local').tier, 'CRITICAL');
    assert.equal(analyzer.classify('.env.production').tier, 'CRITICAL');
    assert.equal(analyzer.classify('backend/.env').tier, 'CRITICAL');
  });

  it('classifies cryptographic keys and certificates as CRITICAL', () => {
    assert.equal(analyzer.classify('id_rsa').tier, 'CRITICAL');
    assert.equal(analyzer.classify('keys/server.key').tier, 'CRITICAL');
    assert.equal(analyzer.classify('cert.pem').tier, 'CRITICAL');
    assert.equal(analyzer.classify('auth.pfx').tier, 'CRITICAL');
  });

  it('classifies credentials and secrets as CRITICAL', () => {
    assert.equal(analyzer.classify('credentials.json').tier, 'CRITICAL');
    assert.equal(analyzer.classify('config/service-account.json').tier, 'CRITICAL');
    assert.equal(analyzer.classify('secrets.yaml').tier, 'CRITICAL');
  });

  it('classifies .git internal metadata as HIGH', () => {
    assert.equal(analyzer.classify('.git/config').tier, 'HIGH');
    assert.equal(analyzer.classify('.git/HEAD').tier, 'HIGH');
  });

  it('classifies CI/CD and package manifests as HIGH', () => {
    assert.equal(analyzer.classify('.github/workflows/ci.yml').tier, 'HIGH');
    assert.equal(analyzer.classify('package.json').tier, 'HIGH');
    assert.equal(analyzer.classify('package-lock.json').tier, 'HIGH');
    assert.equal(analyzer.classify('tsconfig.json').tier, 'HIGH');
  });

  it('classifies standard source code as MEDIUM', () => {
    assert.equal(analyzer.classify('src/index.ts').tier, 'MEDIUM');
    assert.equal(analyzer.classify('app.js').tier, 'MEDIUM');
    assert.equal(analyzer.classify('components/Button.jsx').tier, 'MEDIUM');
    assert.equal(analyzer.classify('styles/main.css').tier, 'MEDIUM');
    assert.equal(analyzer.classify('index.html').tier, 'MEDIUM');
  });

  it('classifies documentation and logs as LOW', () => {
    assert.equal(analyzer.classify('README.md').tier, 'LOW');
    assert.equal(analyzer.classify('LICENSE').tier, 'LOW');
    assert.equal(analyzer.classify('test.log').tier, 'LOW');
    assert.equal(analyzer.classify('notes.txt').tier, 'LOW');
  });
});
