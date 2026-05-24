package sanitizers

import "regexp"

// V33 (v1.6) — Modern deserialization marker detection.
//
// Detect input that LOOKS like a serialized-object payload for runtimes
// where deserialization equals code execution. Each runtime has a
// characteristic byte signature at the start of (or embedded in) a
// serialized blob:
//
//   - Python pickle (protocol 2-5): leading byte 0x80 followed by 0x02-0x05.
//     Reaching pickle.loads() on this with untrusted data = RCE.
//
//   - Java FastJSON: embedded "@type":"com.<class>" autotype marker that
//     FastJSON uses to instantiate arbitrary classes during
//     deserialization. Public CVE corpus has dozens of FastJSON gadget
//     chains 2017-2024.
//
//   - PHP unserialize: O:N:"ClassName":M:{ ... } shape (N = class-name
//     length, M = property count). Targets PHP apps calling unserialize()
//     on user input.
//
//   - Ruby Marshal: magic bytes 0x04 0x08 at position 0. Marshal.load on
//     untrusted data = RCE.
//
//   - .NET BinaryFormatter: leading byte sequence
//     0x00 0x01 0x00 0x00 0x00. Deprecated in .NET 5+ as unsafe; many
//     legacy apps still call it.
//
// API shape
//
// Detection-only helper. Returns the runtime tag the marker indicates,
// or an empty string when no marker matches. Caller decides what to do
// with the signal — typically refuse the request, log a security event,
// or route to a sandboxed handler.
//
// This is NOT wired into SanitizeString because the right response is
// "refuse," not "strip the magic bytes and pass through" — the remaining
// bytes might still deserialize to something dangerous on a forgiving
// parser.

// DeserializeRuntime is the tag returned by DetectDeserialization.
type DeserializeRuntime string

const (
	DeserializePythonPickle         DeserializeRuntime = "python_pickle"
	DeserializeJavaFastJSON         DeserializeRuntime = "java_fastjson"
	DeserializePhpUnserialize       DeserializeRuntime = "php_unserialize"
	DeserializeRubyMarshal          DeserializeRuntime = "ruby_marshal"
	DeserializeDotnetBinaryFormatter DeserializeRuntime = "dotnet_binary_formatter"
	DeserializeNone                 DeserializeRuntime = ""
)

// Python pickle: 0x80 followed by version byte 0x02-0x05.
var picklePattern = regexp.MustCompile(`^\x80[\x02-\x05]`)

// Ruby Marshal magic: 0x04 0x08 at start (Ruby 1.9+).
var rubyMarshalPattern = regexp.MustCompile(`^\x04\x08`)

// .NET BinaryFormatter: 5-byte serialization header.
var dotnetBinFmtPattern = regexp.MustCompile(`^\x00\x01\x00\x00\x00`)

// Java FastJSON: embedded "@type":"<class>" autotype marker.
var fastjsonAutotypePattern = regexp.MustCompile(`"@type"\s*:\s*"[a-zA-Z_$][\w$.]*"`)

// PHP unserialize: O:<len>:"<ClassName>":<count>:{ shape.
var phpUnserializePattern = regexp.MustCompile(`O:\d+:"[a-zA-Z_\\][\w\\]*":\d+:\{`)

// DetectDeserialization detects a serialized-object marker for any
// known runtime. Returns the runtime tag if a marker matches, or
// DeserializeNone if the input looks safe.
//
// Precedence: head-byte markers (pickle / Ruby / .NET) before embedded
// markers (FastJSON / PHP) because head-byte matches are byte-precise
// and faster.
func DetectDeserialization(payload string) DeserializeRuntime {
	if payload == "" {
		return DeserializeNone
	}
	if picklePattern.MatchString(payload) {
		return DeserializePythonPickle
	}
	if rubyMarshalPattern.MatchString(payload) {
		return DeserializeRubyMarshal
	}
	if dotnetBinFmtPattern.MatchString(payload) {
		return DeserializeDotnetBinaryFormatter
	}
	if fastjsonAutotypePattern.MatchString(payload) {
		return DeserializeJavaFastJSON
	}
	if phpUnserializePattern.MatchString(payload) {
		return DeserializePhpUnserialize
	}
	return DeserializeNone
}

// IsSerializedPayload is a convenience boolean wrapper around
// DetectDeserialization.
func IsSerializedPayload(payload string) bool {
	return DetectDeserialization(payload) != DeserializeNone
}
