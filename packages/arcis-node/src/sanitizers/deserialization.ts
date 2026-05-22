/**
 * @module @arcis/node/sanitizers/deserialization
 *
 * V33 — Modern deserialization marker detection (improvements.md §1.2).
 *
 * Detect input that LOOKS like a serialized-object payload for
 * runtimes where deserialization equals code execution: Python
 * pickle, Java FastJSON, PHP unserialize, Ruby Marshal, .NET
 * BinaryFormatter.
 *
 * Detection-only — the right response to a hit is "refuse the
 * request" not "strip the bytes and pass through" (a forgiving
 * parser might still deserialize the remainder to something
 * dangerous). Caller decides.
 *
 * Mirrors `arcis-python/arcis/sanitizers/deserialization.py`. Both
 * SDKs must accept the same base corpus per Pattern 7.
 */

export type DeserializeRuntime =
  | 'python_pickle'
  | 'java_fastjson'
  | 'php_unserialize'
  | 'ruby_marshal'
  | 'dotnet_binary_formatter';

// Python pickle: \x80 followed by version byte 0x02-0x05.
const PICKLE_HEAD = /^\x80[\x02-\x05]/;

// Ruby Marshal magic: \x04\x08 at start (Ruby 1.9+).
const RUBY_MARSHAL_HEAD = /^\x04\x08/;

// .NET BinaryFormatter: 5-byte serialization-header.
const DOTNET_BINFMT_HEAD = /^\x00\x01\x00\x00\x00/;

// Java FastJSON: embedded `"@type":"<class>"`. Match anywhere.
const FASTJSON_AUTOTYPE = /"@type"\s*:\s*"[a-zA-Z_$][\w$.]*"/;

// PHP unserialize: `O:<len>:"<ClassName>":<count>:{` shape.
const PHP_UNSERIALIZE = /O:\d+:"[a-zA-Z_\\][\w\\]*":\d+:\{/;

/**
 * Detect a serialized-object marker for any known runtime.
 *
 * Returns the runtime tag if a marker matches, or null if the input
 * looks safe. Precedence: head-byte markers (pickle / Ruby / .NET)
 * before embedded markers (FastJSON / PHP).
 */
export function detectDeserialization(
  payload: string,
): DeserializeRuntime | null {
  if (typeof payload !== 'string' || payload.length === 0) {
    return null;
  }
  if (PICKLE_HEAD.test(payload)) return 'python_pickle';
  if (RUBY_MARSHAL_HEAD.test(payload)) return 'ruby_marshal';
  if (DOTNET_BINFMT_HEAD.test(payload)) return 'dotnet_binary_formatter';
  if (FASTJSON_AUTOTYPE.test(payload)) return 'java_fastjson';
  if (PHP_UNSERIALIZE.test(payload)) return 'php_unserialize';
  return null;
}

/** Convenience boolean wrapper around `detectDeserialization`. */
export function isSerializedPayload(payload: string): boolean {
  return detectDeserialization(payload) !== null;
}
