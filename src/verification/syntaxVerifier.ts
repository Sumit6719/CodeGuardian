import path from 'path';
import ts from 'typescript';

export interface SyntaxErrorDetail {
  readonly line: number;
  readonly column: number;
  readonly message: string;
}

export interface SyntaxVerificationResult {
  readonly status: 'PASS' | 'FAIL' | 'SKIPPED';
  readonly errors: readonly SyntaxErrorDetail[];
}

export class SyntaxVerifier {
  /**
   * Verifies syntax of code before write or commit.
   * NEVER executes code. Uses deterministic in-memory AST and grammar parsers.
   */
  verify(filePath: string, content: string): SyntaxVerificationResult {
    const ext = path.extname(filePath).toLowerCase();

    switch (ext) {
      case '.ts':
        return this.verifyTypeScript(filePath, content, ts.ScriptKind.TS);
      case '.tsx':
        return this.verifyTypeScript(filePath, content, ts.ScriptKind.TSX);
      case '.js':
      case '.mjs':
      case '.cjs':
        return this.verifyTypeScript(filePath, content, ts.ScriptKind.JS);
      case '.jsx':
        return this.verifyTypeScript(filePath, content, ts.ScriptKind.JSX);
      case '.css':
        return this.verifyCss(content);
      case '.html':
      case '.htm':
        return this.verifyHtml(content);
      case '.json':
        return this.verifyJson(content);
      default:
        return {
          status: 'SKIPPED',
          errors: []
        };
    }
  }

  /**
   * Validates JS/TS/JSX/TSX syntax using the TypeScript Compiler AST parser in memory.
   */
  private verifyTypeScript(
    filePath: string,
    content: string,
    scriptKind: ts.ScriptKind
  ): SyntaxVerificationResult {
    const fileName = path.basename(filePath);
    const sourceFile = ts.createSourceFile(
      fileName,
      content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind
    );

    const diagnostics: readonly ts.Diagnostic[] = (sourceFile as any).parseDiagnostics || [];

    if (diagnostics.length === 0) {
      return {
        status: 'PASS',
        errors: []
      };
    }

    const errors: SyntaxErrorDetail[] = diagnostics.map(d => {
      const start = d.start ?? 0;
      const { line, character } = sourceFile.getLineAndCharacterOfPosition(start);
      return {
        line: line + 1,
        column: character + 1,
        message: ts.flattenDiagnosticMessageText(d.messageText, '\n')
      };
    });

    return {
      status: 'FAIL',
      errors
    };
  }

  /**
   * Validates JSON syntax in memory
   */
  private verifyJson(content: string): SyntaxVerificationResult {
    if (!content.trim()) {
      return {
        status: 'FAIL',
        errors: [{ line: 1, column: 1, message: 'JSON file cannot be empty.' }]
      };
    }

    try {
      JSON.parse(content);
      return { status: 'PASS', errors: [] };
    } catch (err: any) {
      // Extract position from error message if available (e.g. "at position 42")
      let line = 1;
      let column = 1;
      const match = /position\s+(\d+)/i.exec(err.message);
      if (match) {
        const pos = parseInt(match[1], 10);
        const upToPos = content.slice(0, pos);
        const lines = upToPos.split('\n');
        line = lines.length;
        column = lines[lines.length - 1].length + 1;
      }

      return {
        status: 'FAIL',
        errors: [{
          line,
          column,
          message: `JSON Syntax Error: ${err.message}`
        }]
      };
    }
  }

  /**
   * Deterministic CSS grammar and structure validator
   */
  private verifyCss(content: string): SyntaxVerificationResult {
    const errors: SyntaxErrorDetail[] = [];
    const lines = content.split('\n');

    let inComment = false;
    let inString: '"' | "'" | null = null;
    const braceStack: Array<{ char: string; line: number; col: number }> = [];

    for (let l = 0; l < lines.length; l++) {
      const lineStr = lines[l];
      const lineNum = l + 1;

      for (let c = 0; c < lineStr.length; c++) {
        const char = lineStr[c];
        const nextChar = c + 1 < lineStr.length ? lineStr[c + 1] : '';
        const prevChar = c > 0 ? lineStr[c - 1] : '';

        // Comment handling
        if (!inString) {
          if (!inComment && char === '/' && nextChar === '*') {
            inComment = true;
            c++;
            continue;
          }
          if (inComment && char === '*' && nextChar === '/') {
            inComment = false;
            c++;
            continue;
          }
        }

        if (inComment) continue;

        // String handling
        if (char === '"' || char === "'") {
          if (prevChar !== '\\') {
            if (!inString) {
              inString = char;
            } else if (inString === char) {
              inString = null;
            }
          }
          continue;
        }

        if (inString) continue;

        // Structural brace matching: { }, ( ), [ ]
        if (char === '{' || char === '(' || char === '[') {
          braceStack.push({ char, line: lineNum, col: c + 1 });
        } else if (char === '}' || char === ')' || char === ']') {
          const matchingOpening: Record<string, string> = { '}': '{', ')': '(', ']': '[' };
          const expected = matchingOpening[char];
          const last = braceStack.pop();

          if (!last || last.char !== expected) {
            errors.push({
              line: lineNum,
              column: c + 1,
              message: `Unexpected closing bracket '${char}'.`
            });
          }
        }
      }

      // Check for unclosed string on line
      if (inString) {
        errors.push({
          line: lineNum,
          column: lineStr.length,
          message: `Unterminated string constant (${inString}).`
        });
        inString = null;
      }
    }

    if (inComment) {
      errors.push({
        line: lines.length,
        column: 1,
        message: 'Unterminated comment (/* ... */).'
      });
    }

    while (braceStack.length > 0) {
      const unclosed = braceStack.pop()!;
      errors.push({
        line: unclosed.line,
        column: unclosed.col,
        message: `Unclosed bracket '${unclosed.char}'.`
      });
    }

    return {
      status: errors.length === 0 ? 'PASS' : 'FAIL',
      errors
    };
  }

  /**
   * Deterministic HTML structure and tag-balance validator
   */
  private verifyHtml(content: string): SyntaxVerificationResult {
    const errors: SyntaxErrorDetail[] = [];
    const voidElements = new Set([
      'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
      'link', 'meta', 'param', 'source', 'track', 'wbr', '!doctype'
    ]);

    const tagStack: Array<{ tag: string; line: number; col: number }> = [];
    const lines = content.split('\n');

    let inComment = false;
    let inScript = false;
    let inStyle = false;

    // Track tag scanning across lines
    const tagRegex = /<!--|-->|<\/([a-zA-Z0-9_-]+)|<([a-zA-Z0-9_-]+)([^>]*)>|<(\/?)>/g;

    for (let l = 0; l < lines.length; l++) {
      const lineStr = lines[l];
      const lineNum = l + 1;

      // If inside script or style block, check for closing tag
      if (inScript) {
        const closeScript = /<\/script>/i.exec(lineStr);
        if (closeScript) {
          inScript = false;
          // Continue scanning from after </script>
        } else {
          continue;
        }
      }

      if (inStyle) {
        const closeStyle = /<\/style>/i.exec(lineStr);
        if (closeStyle) {
          inStyle = false;
        } else {
          continue;
        }
      }

      let match: RegExpExecArray | null;
      while ((match = tagRegex.exec(lineStr)) !== null) {
        const fullMatch = match[0];
        const col = match.index + 1;

        if (fullMatch === '<!--') {
          inComment = true;
          continue;
        }

        if (fullMatch === '-->') {
          inComment = false;
          continue;
        }

        if (inComment) continue;

        if (fullMatch === '<>' || fullMatch === '</>') {
          errors.push({
            line: lineNum,
            column: col,
            message: `Malformed empty tag '${fullMatch}'.`
          });
          continue;
        }

        // Closing tag: </tag>
        if (match[1]) {
          const closingTag = match[1].toLowerCase();

          if (voidElements.has(closingTag)) {
            errors.push({
              line: lineNum,
              column: col,
              message: `Void element '<${closingTag}>' must not have a closing tag.`
            });
            continue;
          }

          if (tagStack.length === 0) {
            errors.push({
              line: lineNum,
              column: col,
              message: `Unexpected closing tag '</${closingTag}>' without opening tag.`
            });
            continue;
          }

          const last = tagStack.pop()!;
          if (last.tag !== closingTag) {
            errors.push({
              line: lineNum,
              column: col,
              message: `Mismatched closing tag: expected '</${last.tag}>' (opened at line ${last.line}), got '</${closingTag}>'.`
            });
          }
          continue;
        }

        // Opening tag: <tag ...>
        if (match[2]) {
          const openingTag = match[2].toLowerCase();
          const attrString = match[3] || '';
          const isSelfClosing = attrString.trim().endsWith('/') || voidElements.has(openingTag);

          if (openingTag === 'script' && !isSelfClosing) {
            inScript = true;
          } else if (openingTag === 'style' && !isSelfClosing) {
            inStyle = true;
          }

          if (!isSelfClosing) {
            tagStack.push({ tag: openingTag, line: lineNum, col });
          }
        }
      }
    }

    if (inComment) {
      errors.push({
        line: lines.length,
        column: 1,
        message: 'Unterminated HTML comment (<!-- ... -->).'
      });
    }

    while (tagStack.length > 0) {
      const unclosed = tagStack.pop()!;
      errors.push({
        line: unclosed.line,
        column: unclosed.col,
        message: `Unclosed HTML tag '<${unclosed.tag}>'.`
      });
    }

    return {
      status: errors.length === 0 ? 'PASS' : 'FAIL',
      errors
    };
  }
}
