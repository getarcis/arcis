/**
 * V33 — Modern deserialization markers (improvements.md §1.2).
 *
 * Mirrors `tests/sanitizers/test_v33_deserialization.py` in the
 * Python SDK; both SDKs must accept the same base corpus per
 * Pattern 7.
 */
import { describe, it, expect } from 'vitest';
import {
  detectDeserialization,
  isSerializedPayload,
} from '../../src/sanitizers/deserialization';

describe('V33: modern deserialization marker detection', () => {
  it('detects Python pickle protocol 4', () => {
    expect(detectDeserialization('\x80\x04anything')).toBe('python_pickle');
  });

  it('detects Python pickle protocol 5', () => {
    expect(detectDeserialization('\x80\x05anything')).toBe('python_pickle');
  });

  it('detects Python pickle protocol 2', () => {
    expect(detectDeserialization('\x80\x02anything')).toBe('python_pickle');
  });

  it('does NOT match pickle marker mid-string', () => {
    expect(detectDeserialization('hello\x80\x04world')).toBeNull();
  });

  it('detects Ruby Marshal', () => {
    expect(detectDeserialization('\x04\x08[\x06o:\x0bObject\x00')).toBe(
      'ruby_marshal',
    );
  });

  it('detects .NET BinaryFormatter', () => {
    expect(
      detectDeserialization('\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00'),
    ).toBe('dotnet_binary_formatter');
  });

  it('detects Java FastJSON @type autotype', () => {
    const payload =
      '{"@type":"com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "rmi://x/Exploit"}';
    expect(detectDeserialization(payload)).toBe('java_fastjson');
  });

  it('detects FastJSON @type with whitespace', () => {
    expect(detectDeserialization('{ "@type" : "com.evil.Gadget" }')).toBe(
      'java_fastjson',
    );
  });

  it('detects PHP unserialize O: shape', () => {
    const payload = 'O:8:"stdClass":1:{s:4:"user";s:5:"admin";}';
    expect(detectDeserialization(payload)).toBe('php_unserialize');
  });

  it('detects PHP unserialize with namespaced class', () => {
    expect(detectDeserialization('O:18:"App\\\\User\\\\Profile":0:{}')).toBe(
      'php_unserialize',
    );
  });

  it('returns null for safe strings', () => {
    expect(detectDeserialization('hello world')).toBeNull();
    expect(detectDeserialization('{"name": "alice", "age": 30}')).toBeNull();
  });

  it('returns null for empty string', () => {
    expect(detectDeserialization('')).toBeNull();
  });

  it('does not throw on non-string input', () => {
    // @ts-expect-error testing runtime safety on wrong types
    expect(detectDeserialization(null)).toBeNull();
    // @ts-expect-error testing runtime safety on wrong types
    expect(detectDeserialization(123)).toBeNull();
  });

  it('isSerializedPayload is a boolean wrapper', () => {
    expect(isSerializedPayload('\x80\x04x')).toBe(true);
    expect(isSerializedPayload('hello')).toBe(false);
  });

  it('does NOT false-positive on plain English @type mention', () => {
    expect(detectDeserialization('the @type field describes the kind')).toBeNull();
  });

  it('detects PHP shape on already-decoded payload', () => {
    // After the framework JSON-decoded the request body, the inner
    // string `O:5:"User":2:{...}` (no escapes) is what reaches
    // downstream code. The pattern must match THAT form.
    const payload = 'O:5:"User":2:{s:2:"id";i:1;}';
    expect(detectDeserialization(payload)).toBe('php_unserialize');
  });
});
