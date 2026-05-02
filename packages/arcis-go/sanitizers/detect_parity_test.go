// Cross-SDK detection-parity conformance test for Go.
//
// Loads spec/TEST_VECTORS.json and asserts every payload in the
// detect_parity block classifies under the right vector when fed through
// Go's DetectXSS / DetectSQL / DetectPathTraversal / DetectCommandInjection /
// DetectSSTI / DetectXXE.
//
// The same test vectors are run by the Python and Node SDKs (see their
// respective conformance tests). If a payload is caught by one SDK but
// missed by another, that's a Pattern 7 (Cross-SDK Parity Contract)
// violation — the failing assertion points at the SDK that diverged.
//
// Why this matters: each SDK has its own pattern list; without a shared
// parity test the lists drift silently. This Go test was written but
// not run locally because Go SDK tests run inside Docker (Go isn't
// installed on the dev host); CI runs it on every PR.
package sanitizers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type parityCase struct {
	Input    string `json:"input"`
	Expected bool   `json:"expected"`
}

type parityBlock struct {
	XSSPositive     []parityCase `json:"xss_positive"`
	XSSNegative     []parityCase `json:"xss_negative"`
	SQLPositive     []parityCase `json:"sql_positive"`
	SQLNegative     []parityCase `json:"sql_negative"`
	PathPositive    []parityCase `json:"path_positive"`
	PathNegative    []parityCase `json:"path_negative"`
	CommandPositive []parityCase `json:"command_positive"`
	CommandNegative []parityCase `json:"command_negative"`
	SSTIPositive    []parityCase `json:"ssti_positive"`
	SSTINegative    []parityCase `json:"ssti_negative"`
	XXEPositive     []parityCase `json:"xxe_positive"`
	XXENegative     []parityCase `json:"xxe_negative"`
}

type specRoot struct {
	DetectParity *parityBlock `json:"detect_parity"`
}

// loadParity walks up from the test file location until it finds
// spec/TEST_VECTORS.json, mirroring the Python and Node helpers. Lets
// the test pass whether `go test` is invoked from the package root or
// the repo root.
func loadParity(t *testing.T) *parityBlock {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		path := filepath.Join(dir, "spec", "TEST_VECTORS.json")
		raw, err := os.ReadFile(path)
		if err == nil {
			var root specRoot
			if err := json.Unmarshal(raw, &root); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			if root.DetectParity == nil {
				t.Fatalf("detect_parity block missing from %s", path)
			}
			return root.DetectParity
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate spec/TEST_VECTORS.json")
	return nil // unreachable
}

func runDetectorParity(
	t *testing.T,
	name string,
	detector func(string) bool,
	positives []parityCase,
	negatives []parityCase,
) {
	t.Helper()
	for _, c := range positives {
		got := detector(c.Input)
		if !got {
			t.Errorf("%s positive miss: input=%q expected=true got=false", name, c.Input)
		}
	}
	for _, c := range negatives {
		got := detector(c.Input)
		if got {
			t.Errorf("%s negative false-positive: input=%q expected=false got=true", name, c.Input)
		}
	}
}

func TestDetectParity(t *testing.T) {
	parity := loadParity(t)

	t.Run("xss", func(t *testing.T) {
		runDetectorParity(t, "DetectXSS", DetectXSS, parity.XSSPositive, parity.XSSNegative)
	})
	t.Run("sql", func(t *testing.T) {
		runDetectorParity(t, "DetectSQL", DetectSQL, parity.SQLPositive, parity.SQLNegative)
	})
	t.Run("path", func(t *testing.T) {
		runDetectorParity(t, "DetectPathTraversal", DetectPathTraversal,
			parity.PathPositive, parity.PathNegative)
	})
	t.Run("command", func(t *testing.T) {
		runDetectorParity(t, "DetectCommandInjection", DetectCommandInjection,
			parity.CommandPositive, parity.CommandNegative)
	})
	t.Run("ssti", func(t *testing.T) {
		runDetectorParity(t, "DetectSSTI", DetectSSTI, parity.SSTIPositive, parity.SSTINegative)
	})
	t.Run("xxe", func(t *testing.T) {
		runDetectorParity(t, "DetectXXE", DetectXXE, parity.XXEPositive, parity.XXENegative)
	})
}
