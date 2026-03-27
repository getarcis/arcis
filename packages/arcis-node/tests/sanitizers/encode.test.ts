import { describe, it, expect } from 'vitest';
import {
  encodeForHtml,
  encodeForAttribute,
  encodeForJs,
  encodeForUrl,
  encodeForCss,
} from '../../src/sanitizers/encode';

describe('encodeForHtml', () => {
  it('encodes the 5 HTML-dangerous characters', () => {
    expect(encodeForHtml('<script>')).toBe('&lt;script&gt;');
    expect(encodeForHtml('"quotes"')).toBe('&quot;quotes&quot;');
    expect(encodeForHtml("it's")).toBe("it&#x27;s");
    expect(encodeForHtml('a & b')).toBe('a &amp; b');
  });

  it('encodes a full XSS payload', () => {
    expect(encodeForHtml("<script>alert('xss')</script>")).toBe(
      "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
    );
  });

  it('leaves safe alphanumeric text unchanged', () => {
    expect(encodeForHtml('safe text 123')).toBe('safe text 123');
  });

  it('returns empty string for empty input', () => {
    expect(encodeForHtml('')).toBe('');
  });

  it('handles mixed content', () => {
    expect(encodeForHtml('"quotes" & <tags>')).toBe(
      '&quot;quotes&quot; &amp; &lt;tags&gt;'
    );
  });
});

describe('encodeForAttribute', () => {
  it('encodes non-alphanumeric characters as hex entities', () => {
    const result = encodeForAttribute('onclick=alert(1)');
    expect(result).not.toContain('=');
    expect(result).not.toContain('(');
    expect(result).not.toContain(')');
    expect(result).toContain('&#x');
  });

  it('leaves alphanumeric unchanged', () => {
    expect(encodeForAttribute('safe')).toBe('safe');
    expect(encodeForAttribute('ABC123')).toBe('ABC123');
  });

  it('returns empty string for empty input', () => {
    expect(encodeForAttribute('')).toBe('');
  });

  it('encodes spaces', () => {
    expect(encodeForAttribute('a b')).toBe('a&#x20;b');
  });

  it('encodes quotes', () => {
    const result = encodeForAttribute('"hello"');
    expect(result).not.toContain('"');
    expect(result).toContain('&#x22;');
  });

  it('encodes single quotes', () => {
    const result = encodeForAttribute("it's");
    expect(result).not.toContain("'");
    expect(result).toContain('&#x27;');
  });
});

describe('encodeForJs', () => {
  it('escapes non-alphanumeric ASCII as \\xHH', () => {
    const result = encodeForJs("alert('xss')");
    expect(result).not.toContain("'");
    expect(result).not.toContain('(');
    expect(result).toContain('\\x');
  });

  it('escapes </script> to prevent breaking out of script tags', () => {
    const result = encodeForJs('</script>');
    expect(result).not.toContain('<');
    expect(result).not.toContain('/');
    expect(result).not.toContain('>');
  });

  it('leaves alphanumeric unchanged', () => {
    expect(encodeForJs('safe123')).toBe('safe123');
  });

  it('returns empty string for empty input', () => {
    expect(encodeForJs('')).toBe('');
  });

  it('escapes Unicode characters with \\uHHHH', () => {
    const result = encodeForJs('hello\u2028world');
    expect(result).toContain('\\u2028');
  });

  it('escapes backslash', () => {
    const result = encodeForJs('a\\b');
    expect(result).toContain('\\x5C');
  });
});

describe('encodeForUrl', () => {
  it('percent-encodes spaces and special chars', () => {
    expect(encodeForUrl('hello world&foo=bar')).toBe(
      'hello%20world%26foo%3Dbar'
    );
  });

  it('leaves alphanumeric unchanged', () => {
    expect(encodeForUrl('safe123')).toBe('safe123');
  });

  it('returns empty string for empty input', () => {
    expect(encodeForUrl('')).toBe('');
  });

  it('encodes slashes, question marks, hashes', () => {
    const result = encodeForUrl('a/b?c=d#e');
    expect(result).not.toContain('/');
    expect(result).not.toContain('?');
    expect(result).not.toContain('#');
  });

  it('encodes characters not covered by encodeURIComponent', () => {
    const result = encodeForUrl("hello!'()*");
    expect(result).not.toContain("'");
    expect(result).not.toContain('!');
    expect(result).not.toContain('(');
    expect(result).not.toContain(')');
    expect(result).not.toContain('*');
  });
});

describe('encodeForCss', () => {
  it('hex-escapes non-alphanumeric characters', () => {
    const result = encodeForCss('expression(alert(1))');
    expect(result).not.toContain('(');
    expect(result).not.toContain(')');
    expect(result).toContain('\\');
  });

  it('leaves alphanumeric unchanged', () => {
    expect(encodeForCss('red')).toBe('red');
  });

  it('returns empty string for empty input', () => {
    expect(encodeForCss('')).toBe('');
  });

  it('includes trailing space after hex escape per CSS spec', () => {
    const result = encodeForCss(';');
    // CSS spec: \HH followed by a space
    expect(result).toMatch(/\\[0-9A-F]+ $/);
  });

  it('encodes semicolons to prevent CSS injection', () => {
    const result = encodeForCss('red; background: url(evil)');
    expect(result).not.toContain(';');
    expect(result).not.toContain(':');
    expect(result).not.toContain('(');
  });
});
