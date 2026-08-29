import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SyntaxVerifier } from '../../../src/verification/syntaxVerifier.js';

describe('SyntaxVerifier Isolated AST & Grammar Verification', () => {
  const verifier = new SyntaxVerifier();

  describe('JavaScript (.js)', () => {
    it('passes on valid JavaScript code', () => {
      const code = `
        function calculateTotal(items) {
          return items.reduce((sum, item) => sum + item.price, 0);
        }
        export default calculateTotal;
      `;
      const res = verifier.verify('src/calc.js', code);
      assert.equal(res.status, 'PASS');
      assert.equal(res.errors.length, 0);
    });

    it('fails on syntactically invalid JavaScript with error positions', () => {
      const code = `
        function broken(a, b {
          return a + b;
        }
      `;
      const res = verifier.verify('src/broken.js', code);
      assert.equal(res.status, 'FAIL');
      assert.ok(res.errors.length > 0);
      assert.ok(res.errors[0].line >= 2);
    });
  });

  describe('TypeScript (.ts)', () => {
    it('passes on valid TypeScript code with types and generics', () => {
      const code = `
        interface User<T> {
          id: string;
          data: T;
          createdAt: Date;
        }
        export async function fetchUser<T>(id: string): Promise<User<T>> {
          return { id, data: {} as T, createdAt: new Date() };
        }
      `;
      const res = verifier.verify('src/user.ts', code);
      assert.equal(res.status, 'PASS');
      assert.equal(res.errors.length, 0);
    });

    it('fails on syntactically invalid TypeScript', () => {
      const code = `
        interface Bad {
          name: string
          age: = 12;
        }
      `;
      const res = verifier.verify('src/bad.ts', code);
      assert.equal(res.status, 'FAIL');
      assert.ok(res.errors.length > 0);
    });
  });

  describe('React JSX (.jsx) & TSX (.tsx)', () => {
    it('passes on valid JSX', () => {
      const code = `
        import React from 'react';
        export const Header = ({ title }) => (
          <header className="site-header">
            <h1>{title}</h1>
            <nav><a href="/home">Home</a></nav>
          </header>
        );
      `;
      const res = verifier.verify('src/Header.jsx', code);
      assert.equal(res.status, 'PASS');
    });

    it('fails on invalid JSX (unclosed tag)', () => {
      const code = `
        export const Bad = () => (
          <div><span>Hello</div>
        );
      `;
      const res = verifier.verify('src/Bad.jsx', code);
      assert.equal(res.status, 'FAIL');
      assert.ok(res.errors.length > 0);
    });

    it('passes on valid TSX with typed props', () => {
      const code = `
        import React from 'react';
        interface ButtonProps {
          label: string;
          onClick: () => void;
        }
        export const Button: React.FC<ButtonProps> = ({ label, onClick }) => (
          <button onClick={onClick}>{label}</button>
        );
      `;
      const res = verifier.verify('src/Button.tsx', code);
      assert.equal(res.status, 'PASS');
    });
  });

  describe('HTML (.html)', () => {
    it('passes on valid HTML5 with doctype and void elements', () => {
      const html = `
        <!DOCTYPE html>
        <html lang="en">
          <head>
            <meta charset="UTF-8">
            <title>Test Page</title>
            <link rel="stylesheet" href="style.css">
          </head>
          <body>
            <div id="app">
              <h1>Title</h1>
              <img src="logo.png" alt="Logo">
              <br>
              <input type="text" name="query">
            </div>
          </body>
        </html>
      `;
      const res = verifier.verify('public/index.html', html);
      assert.equal(res.status, 'PASS');
      assert.equal(res.errors.length, 0);
    });

    it('fails on mismatched HTML closing tag', () => {
      const html = `
        <div class="container">
          <p>Mismatched</span>
        </div>
      `;
      const res = verifier.verify('public/bad.html', html);
      assert.equal(res.status, 'FAIL');
      assert.ok(res.errors.length > 0);
      assert.match(res.errors[0].message, /mismatched closing tag/i);
    });

    it('fails on unclosed HTML tag', () => {
      const html = `
        <div class="unclosed">
          <section>Content
        </div>
      `;
      const res = verifier.verify('public/unclosed.html', html);
      assert.equal(res.status, 'FAIL');
      assert.ok(res.errors.length > 0);
    });
  });

  describe('CSS (.css)', () => {
    it('passes on valid CSS declarations and media queries', () => {
      const css = `
        :root {
          --primary-color: #3b82f6;
        }
        body {
          margin: 0;
          font-family: sans-serif;
        }
        @media (max-width: 768px) {
          .container {
            padding: 10px;
          }
        }
      `;
      const res = verifier.verify('styles/main.css', css);
      assert.equal(res.status, 'PASS');
      assert.equal(res.errors.length, 0);
    });

    it('fails on unclosed CSS curly brace', () => {
      const css = `
        body {
          color: blue;
        
        .card {
          padding: 8px;
        }
      `;
      const res = verifier.verify('styles/bad.css', css);
      assert.equal(res.status, 'FAIL');
      assert.ok(res.errors.length > 0);
      assert.match(res.errors[0].message, /unclosed bracket/i);
    });

    it('fails on unterminated CSS comment', () => {
      const css = `
        /* This comment is never closed
        body { color: red; }
      `;
      const res = verifier.verify('styles/comment.css', css);
      assert.equal(res.status, 'FAIL');
      assert.match(res.errors[0].message, /unterminated comment/i);
    });
  });

  describe('JSON (.json)', () => {
    it('passes on valid JSON', () => {
      const json = JSON.stringify({ name: 'CodeGuardian', version: '0.2.0', active: true }, null, 2);
      const res = verifier.verify('package.json', json);
      assert.equal(res.status, 'PASS');
    });

    it('fails on invalid JSON syntax', () => {
      const json = '{ "broken": true, }'; // trailing comma
      const res = verifier.verify('bad.json', json);
      assert.equal(res.status, 'FAIL');
      assert.ok(res.errors.length > 0);
    });
  });

  describe('Non-code files', () => {
    it('skips verification for documentation and text files', () => {
      const res = verifier.verify('README.md', '# Documentation\nAny raw text...');
      assert.equal(res.status, 'SKIPPED');
      assert.equal(res.errors.length, 0);
    });
  });
});
