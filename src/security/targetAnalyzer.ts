import path from 'path';
import { SensitivityTier } from '../core/types.js';

export interface SensitivityPattern {
  tier: SensitivityTier;
  pattern: RegExp;
  description: string;
}

export class TargetAnalyzer {
  private readonly rules: SensitivityPattern[];

  constructor(customRules?: SensitivityPattern[]) {
    this.rules = [
      // Custom rules override defaults if provided
      ...(customRules || []),

      // CRITICAL: Secrets, keys, credentials, environment variables
      {
        tier: 'CRITICAL',
        pattern: /(^|\/)\.env(\..+)?$/i,
        description: 'Environment file containing potential secrets'
      },
      {
        tier: 'CRITICAL',
        pattern: /\.(pem|key|pfx|p12|pkcs12)$/i,
        description: 'Private cryptographic key or certificate bundle'
      },
      {
        tier: 'CRITICAL',
        pattern: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\..+)?$/i,
        description: 'SSH private key file'
      },
      {
        tier: 'CRITICAL',
        pattern: /(^|\/)(credentials|secrets|service[-_]?account|private[-_]?key).*\.(json|yml|yaml|ini|xml)$/i,
        description: 'Explicit credential/secret storage file'
      },

      // HIGH: Git metadata, CI/CD, build & package managers
      {
        tier: 'HIGH',
        pattern: /(^|\/)\.git(\/|$)/i,
        description: 'Git internal metadata and configuration'
      },
      {
        tier: 'HIGH',
        pattern: /(^|\/)\.github\/(workflows|actions)(\/|$)/i,
        description: 'GitHub Actions / CI/CD pipeline definition'
      },
      {
        tier: 'HIGH',
        pattern: /(^|\/)(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.toml|go\.mod|requirements\.txt|Gemfile)$/i,
        description: 'Core package manifest or lockfile'
      },
      {
        tier: 'HIGH',
        pattern: /(^|\/)(tsconfig.*\.json|webpack.*\.js|vite\.config.*|next\.config.*|Dockerfile|docker-compose.*\.yml)$/i,
        description: 'Build or container orchestration configuration'
      },

      // LOW: Documentation, temporary files, logs, tests output
      {
        tier: 'LOW',
        pattern: /\.(md|txt|markdown|rst|adoc)$/i,
        description: 'Documentation or text file'
      },
      {
        tier: 'LOW',
        pattern: /(^|\/)(LICENSE|CHANGELOG|NOTICE|AUTHORS)$/i,
        description: 'Standard repository documentation file'
      },
      {
        tier: 'LOW',
        pattern: /(^|\/)(coverage|\.temp|\.tmp|logs?)\/|\.(log|tmp|bak)$/i,
        description: 'Temporary or test log artifact'
      },

      // MEDIUM: Source code and application assets (default tier for non-critical code)
      {
        tier: 'MEDIUM',
        pattern: /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|html|htm|css|scss|sass|less|json|py|rb|go|rs|java|c|cpp|h|cs|php|sql|sh|bash)$/i,
        description: 'Application source code or stylesheet'
      }
    ];
  }

  /**
   * Analyzes a normalized relative path and returns its sensitivity tier and description.
   */
  classify(relativePath: string): { tier: SensitivityTier; reason: string } {
    // Normalize slashes to forward slashes
    const normalized = relativePath.replace(/\\/g, '/');

    for (const rule of this.rules) {
      if (rule.pattern.test(normalized)) {
        return {
          tier: rule.tier,
          reason: rule.description
        };
      }
    }

    // Default to MEDIUM if not matched by any explicit low/high/critical rule
    return {
      tier: 'MEDIUM',
      reason: 'General project file'
    };
  }
}
