/**
 * SSTI (Server-Side Template Injection) Sanitizer Tests
 * Tests for src/sanitizers/ssti.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeSsti, detectSsti } from '../../src/sanitizers/ssti';

describe('detectSsti', () => {
  describe('Jinja2 / Twig / Nunjucks ({{ }})', () => {
    it('should detect {{7*7}}', () => {
      expect(detectSsti('{{7*7}}')).toBe(true);
    });

    it('should detect {{ 7 * 7 }} with spaces', () => {
      expect(detectSsti('{{ 7 * 7 }}')).toBe(true);
    });

    it('should detect {{config.items()}}', () => {
      expect(detectSsti('{{config.items()}}')).toBe(true);
    });

    it('should detect config leak {{config["SECRET_KEY"]}}', () => {
      expect(detectSsti('{{config["SECRET_KEY"]}}')).toBe(true);
    });

    it('should detect Python sandbox escape via __class__', () => {
      expect(detectSsti("{{''.__class__.__mro__[1].__subclasses__()}}")).toBe(true);
    });

    it('should detect Jinja2 self reference', () => {
      expect(detectSsti('{{self._TemplateReference__context}}')).toBe(true);
    });

    it('should detect Jinja2 request object', () => {
      expect(detectSsti('{{request.application.__self__._get_data_for_json}}')).toBe(true);
    });

    it('should detect lipsum abuse', () => {
      expect(detectSsti('{{lipsum.__globals__}}')).toBe(true);
    });

    it('should detect cycler abuse', () => {
      expect(detectSsti('{{cycler.__init__.__globals__}}')).toBe(true);
    });
  });

  describe('Freemarker / Thymeleaf / Spring EL (${ })', () => {
    it('should detect ${7*7}', () => {
      expect(detectSsti('${7*7}')).toBe(true);
    });

    it('should detect ${T(java.lang.Runtime).getRuntime().exec("id")}', () => {
      expect(detectSsti('${T(java.lang.Runtime).getRuntime().exec("id")}')).toBe(true);
    });

    it('should detect Spring EL ${applicationContext}', () => {
      expect(detectSsti('${applicationContext}')).toBe(true);
    });
  });

  describe('ERB / EJS (<%= %>)', () => {
    it('should detect <%= 7*7 %>', () => {
      expect(detectSsti('<%= 7*7 %>')).toBe(true);
    });

    it('should detect <% system("id") %>', () => {
      expect(detectSsti('<% system("id") %>')).toBe(true);
    });

    it('should detect <%- include("file") %>', () => {
      expect(detectSsti('<%- include("file") %>')).toBe(true);
    });
  });

  describe('Pug / Jade / Slim (#{ })', () => {
    it('should detect #{7*7}', () => {
      expect(detectSsti('#{7*7}')).toBe(true);
    });

    it('should detect #{root.process.mainModule.require("child_process").execSync("id")}', () => {
      expect(detectSsti('#{root.process.mainModule.require("child_process").execSync("id")}')).toBe(true);
    });
  });

  describe('Python dunder chains', () => {
    it('should detect __class__', () => {
      expect(detectSsti('__class__')).toBe(true);
    });

    it('should detect __mro__', () => {
      expect(detectSsti('__mro__')).toBe(true);
    });

    it('should detect __subclasses__', () => {
      expect(detectSsti('__subclasses__')).toBe(true);
    });

    it('should detect __globals__', () => {
      expect(detectSsti('__globals__')).toBe(true);
    });

    it('should detect __builtins__', () => {
      expect(detectSsti('__builtins__')).toBe(true);
    });

    it('should detect __import__', () => {
      expect(detectSsti('__import__')).toBe(true);
    });

    it('should be case-insensitive for dunders', () => {
      expect(detectSsti('__CLASS__')).toBe(true);
      expect(detectSsti('__Globals__')).toBe(true);
    });
  });

  describe('Safe inputs (no false positives)', () => {
    it('should not flag plain text', () => {
      expect(detectSsti('hello world')).toBe(false);
    });

    it('should not flag normal curly braces in JSON', () => {
      expect(detectSsti('{"key": "value"}')).toBe(false);
    });

    it('should not flag single curly braces', () => {
      expect(detectSsti('{name}')).toBe(false);
    });

    it('should not flag CSS', () => {
      expect(detectSsti('.class { color: red; }')).toBe(false);
    });

    it('should not flag __init__ or __name__', () => {
      expect(detectSsti('__init__')).toBe(false);
      expect(detectSsti('__name__')).toBe(false);
    });

    it('should return false for non-string input', () => {
      expect(detectSsti(123 as any)).toBe(false);
      expect(detectSsti(null as any)).toBe(false);
    });
  });
});

describe('sanitizeSsti', () => {
  describe('Removes template expressions', () => {
    it('should remove {{7*7}}', () => {
      expect(sanitizeSsti('result: {{7*7}}')).toBe('result: ');
    });

    it('should remove ${7*7}', () => {
      expect(sanitizeSsti('result: ${7*7}')).toBe('result: ');
    });

    it('should remove <%= 7*7 %>', () => {
      expect(sanitizeSsti('result: <%= 7*7 %>')).toBe('result: ');
    });

    it('should remove #{7*7}', () => {
      expect(sanitizeSsti('result: #{7*7}')).toBe('result: ');
    });

    it('should remove Python dunder chains', () => {
      expect(sanitizeSsti('foo.__class__.bar')).toBe('foo..bar');
    });

    it('should remove multiple template expressions', () => {
      expect(sanitizeSsti('{{a}}+{{b}}')).toBe('+');
    });

    it('should remove complex Jinja2 payload', () => {
      const payload = "{{''.__class__.__mro__[1].__subclasses__()}}";
      expect(sanitizeSsti(payload)).toBe('');
    });
  });

  describe('Preserves safe content', () => {
    it('should preserve plain text', () => {
      expect(sanitizeSsti('hello world')).toBe('hello world');
    });

    it('should preserve JSON-like strings', () => {
      expect(sanitizeSsti('{"key": "value"}')).toBe('{"key": "value"}');
    });
  });

  describe('Threat collection', () => {
    it('should collect threats when requested', () => {
      const result = sanitizeSsti('{{7*7}}', true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0].type).toBe('ssti');
      expect(result.threats[0].original).toBe('{{7*7}}');
    });

    it('should report no threats for safe input', () => {
      const result = sanitizeSsti('safe string', true);
      expect(result.wasSanitized).toBe(false);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('Edge cases', () => {
    it('should handle non-string input', () => {
      expect(sanitizeSsti(42 as any)).toBe('42');
    });

    it('should handle empty string', () => {
      expect(sanitizeSsti('')).toBe('');
    });
  });
});
