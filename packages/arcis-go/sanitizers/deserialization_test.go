package sanitizers

import "testing"

// Python pickle protocol 2-5 head markers.
func TestDetectDeserialization_PythonPickle(t *testing.T) {
	cases := []string{
		"\x80\x02rest of pickle bytes",
		"\x80\x03more bytes",
		"\x80\x04another payload",
		"\x80\x05protocol 5",
	}
	for _, p := range cases {
		t.Run(p[:2], func(t *testing.T) {
			got := DetectDeserialization(p)
			if got != DeserializePythonPickle {
				t.Errorf("expected python_pickle, got %q for %q", got, p)
			}
			if !IsSerializedPayload(p) {
				t.Errorf("expected IsSerializedPayload=true for %q", p)
			}
		})
	}
}

func TestDetectDeserialization_RubyMarshal(t *testing.T) {
	got := DetectDeserialization("\x04\x08\x49\x22\x05hello")
	if got != DeserializeRubyMarshal {
		t.Errorf("expected ruby_marshal, got %q", got)
	}
}

func TestDetectDeserialization_DotnetBinaryFormatter(t *testing.T) {
	got := DetectDeserialization("\x00\x01\x00\x00\x00\x12\xff\xff\xff\xff")
	if got != DeserializeDotnetBinaryFormatter {
		t.Errorf("expected dotnet_binary_formatter, got %q", got)
	}
}

func TestDetectDeserialization_JavaFastJSON(t *testing.T) {
	cases := []string{
		`{"@type":"com.evil.Gadget", "x": 1}`,
		`{"key": {"@type":"java.util.HashMap"}}`,
		`{"@type" : "com.fastjson.Bypass"}`,
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			got := DetectDeserialization(p)
			if got != DeserializeJavaFastJSON {
				t.Errorf("expected java_fastjson, got %q for %q", got, p)
			}
		})
	}
}

func TestDetectDeserialization_PhpUnserialize(t *testing.T) {
	cases := []string{
		`O:8:"stdClass":1:{s:1:"x";i:1;}`,
		`O:14:"PhpEvilClass":3:{s:4:"data";`,
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			got := DetectDeserialization(p)
			if got != DeserializePhpUnserialize {
				t.Errorf("expected php_unserialize, got %q for %q", got, p)
			}
		})
	}
}

func TestDetectDeserialization_Safe(t *testing.T) {
	cases := []string{
		"",
		"hello world",
		`{"normal": "json"}`,
		`{"type": "string but no @"}`, // no @type
		"plain text",
		`{"name": "Alice", "age": 30}`,
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			got := DetectDeserialization(p)
			if got != DeserializeNone {
				t.Errorf("expected DeserializeNone, got %q for %q", got, p)
			}
			if IsSerializedPayload(p) {
				t.Errorf("expected IsSerializedPayload=false for %q", p)
			}
		})
	}
}

func TestDetectDeserialization_PrecedenceHeadBeatsEmbedded(t *testing.T) {
	// Pickle head + FastJSON marker — head should win.
	p := "\x80\x04...\"@type\":\"com.evil.Gadget\"..."
	got := DetectDeserialization(p)
	if got != DeserializePythonPickle {
		t.Errorf("expected python_pickle (head precedence), got %q", got)
	}
}
