import path from 'path';

export interface ParsedCommand {
  readonly rawCommand: string;
  readonly executable: string;
  readonly args: readonly string[];
  readonly env: Record<string, string>;
  readonly hasShellOperators: boolean;
  readonly isDangerous: boolean;
  readonly dangerReason?: string;
}

export class CommandParser {
  /**
   * Tokenizes a command string safely respecting quotes and escape characters.
   */
  tokenize(commandStr: string): string[] {
    const tokens: string[] = [];
    let currentToken = '';
    let inDoubleQuotes = false;
    let inSingleQuotes = false;
    let escaped = false;

    const trimmed = commandStr.trim();

    for (let i = 0; i < trimmed.length; i++) {
      const char = trimmed[i];

      if (escaped) {
        currentToken += char;
        escaped = false;
        continue;
      }

      if (char === '\\') {
        escaped = true;
        continue;
      }

      if (char === '"') {
        if (!inSingleQuotes) {
          inDoubleQuotes = !inDoubleQuotes;
        } else {
          currentToken += char;
        }
        continue;
      }

      if (char === "'") {
        if (!inDoubleQuotes) {
          inSingleQuotes = !inSingleQuotes;
        } else {
          currentToken += char;
        }
        continue;
      }

      if (char === ' ' || char === '\t') {
        if (inDoubleQuotes || inSingleQuotes) {
          currentToken += char;
        } else {
          if (currentToken.length > 0) {
            tokens.push(currentToken);
            currentToken = '';
          }
        }
        continue;
      }

      currentToken += char;
    }

    if (currentToken.length > 0) {
      tokens.push(currentToken);
    }

    return tokens;
  }

  /**
   * Parses a raw command string and performs deterministic structural threat analysis.
   */
  parse(commandStr: string): ParsedCommand {
    const rawTokens = this.tokenize(commandStr);
    
    if (rawTokens.length === 0) {
      return {
        rawCommand: commandStr,
        executable: '',
        args: [],
        env: {},
        hasShellOperators: false,
        isDangerous: true,
        dangerReason: 'Empty command string.'
      };
    }

    // 1. Detect Shell Operators / Chaining / Redirection
    // We check all tokens (and the raw string) for shell metacharacters:
    // &&, ||, ;, |, >, <, >>, $(, `, &, and newlines
    const shellMetachars = ['&&', '||', ';', '|', '>', '<', '>>', '<<', '&', '`', '$(', '\n', '\r'];
    let hasShellOperators = false;
    for (const char of shellMetachars) {
      if (commandStr.includes(char)) {
        hasShellOperators = true;
      }
    }
    // Also check token level
    for (const token of rawTokens) {
      if (shellMetachars.some(op => token.includes(op))) {
        hasShellOperators = true;
      }
    }

    // 2. Parse Environment Variable Prefix (e.g., NODE_ENV=test npm test)
    const env: Record<string, string> = {};
    let tokenIndex = 0;
    while (tokenIndex < rawTokens.length) {
      const token = rawTokens[tokenIndex];
      const eqIdx = token.indexOf('=');
      // Must have = and name must be valid identifier (no slash, no dot, etc.)
      if (eqIdx > 0 && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(token.slice(0, eqIdx))) {
        const name = token.slice(0, eqIdx);
        const value = token.slice(eqIdx + 1);
        env[name] = value;
        tokenIndex++;
      } else {
        break;
      }
    }

    if (tokenIndex >= rawTokens.length) {
      return {
        rawCommand: commandStr,
        executable: '',
        args: [],
        env,
        hasShellOperators,
        isDangerous: true,
        dangerReason: 'No executable found after environment variable definitions.'
      };
    }

    const rawExecutable = rawTokens[tokenIndex];
    const args = rawTokens.slice(tokenIndex + 1);

    // Resolve binary basename (e.g. C:\bin\node.exe -> node, ./my-script.sh -> my-script.sh)
    const executable = path.basename(rawExecutable).toLowerCase().replace(/\.exe$/, '');

    // 3. Analyze Risks (Privilege escalation, Network, Filesystem destruction, Package installation)
    let isDangerous = false;
    let dangerReason: string | undefined = undefined;

    // A. Privilege escalation block
    const privilegeEscalationBinaries = new Set(['sudo', 'su', 'runas', 'chmod', 'chown']);
    if (privilegeEscalationBinaries.has(executable)) {
      isDangerous = true;
      dangerReason = `Privilege escalation attempt detected via binary: ${rawExecutable}`;
    }

    // B. Destructive filesystem operations block
    const destructiveBinaries = new Set(['rm', 'del', 'rmdir', 'remove-item', 'erase', 'rd']);
    if (destructiveBinaries.has(executable)) {
      // Analyze arguments for dangerous flags/targets
      const hasRecursive = args.some(arg => arg.includes('-r') || arg.includes('-f') || arg.includes('/s') || arg.includes('/q'));
      const targetsRoot = args.some(arg => arg === '/' || arg === '/*' || arg === '\\' || arg === '\\*' || arg === '.' || arg === '..');

      if (hasRecursive || targetsRoot || executable === 'del' || executable === 'rmdir' || executable === 'erase' || executable === 'rd') {
        isDangerous = true;
        dangerReason = `Dangerous filesystem destruction command detected: ${commandStr}`;
      }
    }

    // C. Explicitly blocked dangerous system binaries
    const blockedSystemBinaries = new Set([
      'powershell', 'pwsh', 'cmd', 'bash', 'sh', 'zsh', 'ash', 'csh', 'ksh',
      'curl', 'wget', 'nc', 'netcat', 'ssh', 'scp', 'ftp', 'telnet',
      'python', 'python3', 'node', 'perl', 'ruby', 'gcc', 'clang', 'make',
      'start-process', 'invoke-webrequest', 'certutil', 'bitsadmin', 'powershell-ise'
    ]);
    if (blockedSystemBinaries.has(executable)) {
      isDangerous = true;
      dangerReason = `Execution of arbitrary script interpreters, compilers, or network downloaders is blocked: ${rawExecutable}`;
    }

    // D. Package installation checks
    const packageManagers = new Set(['npm', 'yarn', 'pnpm']);
    if (packageManagers.has(executable)) {
      const isInstall = args.some(arg => ['install', 'i', 'add', 'update', 'upgrade'].includes(arg.toLowerCase()));
      if (isInstall) {
        isDangerous = true;
        dangerReason = `Package installation or update commands require explicit manual approval: ${commandStr}`;
      }
    }

    // E. Windows specific shell injection warnings / operators inside raw args
    if (hasShellOperators) {
      isDangerous = true;
      dangerReason = `Command chaining, pipes, or shell redirection operators are strictly blocked: ${commandStr}`;
    }

    return {
      rawCommand: commandStr,
      executable,
      args,
      env,
      hasShellOperators,
      isDangerous,
      dangerReason
    };
  }
}
