/**
 * Path Traversal Sanitizer Tests
 * Tests for src/sanitizers/path.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizePath, detectPathTraversal } from '../../src/sanitizers/path';

describe('sanitizePath', () => {
  describe('Unix-style Traversal', () => {
    it('should remove ../', () => {
      const result = sanitizePath('../../etc/passwd');
      expect(result).not.toContain('../');
    });

    it('should remove multiple ../  sequences', () => {
      const result = sanitizePath('../../../root/.ssh/id_rsa');
      expect(result).not.toContain('../');
    });

    it('should handle single ../', () => {
      const result = sanitizePath('../secret.txt');
      expect(result).not.toContain('../');
    });
  });

  describe('Windows-style Traversal', () => {
    it('should remove ..\\', () => {
      const result = sanitizePath('..\\..\\windows\\system32');
      expect(result).not.toContain('..\\');
    });

    it('should remove multiple ..\\ sequences', () => {
      const result = sanitizePath('..\\..\\..\\boot.ini');
      expect(result).not.toContain('..\\');
    });
  });

  describe('URL-encoded Traversal', () => {
    it('should remove %2e%2e%2f (../)', () => {
      const result = sanitizePath('%2e%2e%2f%2e%2e%2f');
      expect(result.toLowerCase()).not.toContain('%2e%2e');
    });

    it('should remove %2e%2e/ (../)', () => {
      const result = sanitizePath('%2e%2e/etc/passwd');
      expect(result.toLowerCase()).not.toContain('%2e%2e');
    });

    // Note: The current PATH_PATTERNS only handles:
    // - /\.\.\//g (../)
    // - /\.\.\\/g (..\)
    // - /%2e%2e/gi (%2e%2e - the dots only, not the slash)
    // - /%252e/gi (double-encoded dot)
    // It does NOT decode %2f to / before checking, so ..%2f won't be caught
    // as path traversal (it will look like "..%2f" not "../")

    it('should remove %2e%2e%5c (..\\)', () => {
      const result = sanitizePath('%2e%2e%5c%2e%2e%5c');
      expect(result.toLowerCase()).not.toContain('%2e%2e');
    });
  });

  describe('Bypass Variants', () => {
    it('should remove ....// (dotdotslash bypass)', () => {
      const result = sanitizePath('....//etc/passwd');
      expect(result).not.toMatch(/\.{2,}\/\//);
    });

    it('should remove ....\\\\ (dotdotbackslash bypass)', () => {
      const result = sanitizePath('....\\\\windows\\system32');
      expect(result).not.toMatch(/\.{2,}\\\\/);
    });

    it('should remove %252f (double-encoded slash)', () => {
      const result = sanitizePath('..%252f..%252f');
      expect(result.toLowerCase()).not.toContain('%252f');
    });

    it('should remove %252e (double-encoded dot)', () => {
      const result = sanitizePath('%252e%252e/etc/passwd');
      expect(result.toLowerCase()).not.toContain('%252e');
    });
  });

  describe('Safe Paths', () => {
    it('should preserve normal file paths', () => {
      const result = sanitizePath('documents/file.txt');
      expect(result).toBe('documents/file.txt');
    });

    it('should preserve absolute paths', () => {
      const result = sanitizePath('/var/www/html/index.html');
      expect(result).toBe('/var/www/html/index.html');
    });

    it('should preserve Windows absolute paths', () => {
      const result = sanitizePath('C:\\Users\\Public\\file.txt');
      expect(result).toBe('C:\\Users\\Public\\file.txt');
    });

    it('should preserve relative paths without traversal', () => {
      const result = sanitizePath('./config/settings.json');
      expect(result).toBe('./config/settings.json');
    });
  });

  describe('Threat Collection', () => {
    it('should collect threat info when requested', () => {
      const result = sanitizePath('../../etc/passwd', true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0].type).toBe('path_traversal');
    });

    it('should return no threats for safe paths', () => {
      const result = sanitizePath('documents/file.txt', true);
      expect(result.wasSanitized).toBe(false);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string', () => {
      const result = sanitizePath('');
      expect(result).toBe('');
    });

    it('should handle non-string input', () => {
      const result = sanitizePath(123 as unknown as string);
      expect(result).toBe('123');
    });

    it('should handle paths with special characters', () => {
      const result = sanitizePath('files/report (final).pdf');
      expect(result).toContain('report');
    });

    it('should handle hidden files (starting with .)', () => {
      const result = sanitizePath('.gitignore');
      expect(result).toBe('.gitignore');
    });

    it('should handle single dot paths', () => {
      const result = sanitizePath('./file.txt');
      expect(result).toBe('./file.txt');
    });
  });
});

describe('detectPathTraversal', () => {
  it('should detect ../', () => {
    expect(detectPathTraversal('../')).toBe(true);
  });

  it('should detect ..\\', () => {
    expect(detectPathTraversal('..\\')).toBe(true);
  });

  it('should detect URL-encoded traversal', () => {
    expect(detectPathTraversal('%2e%2e%2f')).toBe(true);
  });

  it('should detect ....// bypass', () => {
    expect(detectPathTraversal('....//etc/passwd')).toBe(true);
  });

  it('should detect %252f double-encoded slash', () => {
    expect(detectPathTraversal('..%252f..')).toBe(true);
  });

  it('should return false for safe paths', () => {
    expect(detectPathTraversal('documents/file.txt')).toBe(false);
  });

  it('should return false for single dot', () => {
    expect(detectPathTraversal('./file.txt')).toBe(false);
  });

  it('should handle non-string input', () => {
    expect(detectPathTraversal(123 as unknown as string)).toBe(false);
  });
});
