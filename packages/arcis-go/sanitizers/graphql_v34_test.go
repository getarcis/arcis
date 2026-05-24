package sanitizers

import (
	"strings"
	"testing"
)

// V34 — alias bomb detection.

func TestGraphQL_V34_AliasCount_LegitimateLow(t *testing.T) {
	q := `query { a: user(id: 1) { name } b: user(id: 2) { name } }`
	r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
	if r.Blocked {
		t.Fatalf("legit 2-alias query should not block, reason=%s", r.Reason)
	}
	if r.Aliases < 2 {
		t.Errorf("expected aliases >= 2, got %d", r.Aliases)
	}
}

func TestGraphQL_V34_AliasBomb_Blocks(t *testing.T) {
	// 60 aliased fields, well above default 50 cap.
	var b strings.Builder
	b.WriteString("query {")
	for i := 0; i < 60; i++ {
		b.WriteString(" a")
		// vary the label
		for d := i; d > 0; d /= 10 {
			b.WriteByte(byte('0' + d%10))
		}
		b.WriteString(": user")
	}
	b.WriteString(" }")
	r := InspectGraphqlQuery(b.String(), NewGraphqlGuardOptions())
	if !r.Blocked {
		t.Fatalf("alias-bomb (60 aliases, cap 50) should block")
	}
	if r.Reason != "aliases" {
		t.Errorf("expected reason=aliases, got %q", r.Reason)
	}
	if r.Aliases < 60 {
		t.Errorf("expected aliases >= 60, got %d", r.Aliases)
	}
}

func TestGraphQL_V34_AliasMax_Tunable(t *testing.T) {
	opts := NewGraphqlGuardOptions()
	opts.MaxAliases = 5
	q := `query { a: f, b: f, c: f, d: f, e: f, fff: f, g: f }`
	r := InspectGraphqlQuery(q, opts)
	if !r.Blocked {
		t.Fatalf("7 aliases over cap 5 should block")
	}
	if r.Reason != "aliases" {
		t.Errorf("expected reason=aliases, got %q", r.Reason)
	}
}

// V34 — fragment cycle detection.

func TestGraphQL_V34_FragmentCycle_DirectSelfReference(t *testing.T) {
	q := `
		query Q { user { ...A } }
		fragment A on User { id ...A }
	`
	r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
	if !r.Blocked {
		t.Fatalf("direct self-reference fragment should block")
	}
	if r.Reason != "fragment_cycle" {
		t.Errorf("expected reason=fragment_cycle, got %q", r.Reason)
	}
}

func TestGraphQL_V34_FragmentCycle_Indirect(t *testing.T) {
	q := `
		query Q { user { ...A } }
		fragment A on User { id ...B }
		fragment B on User { name ...A }
	`
	r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
	if !r.Blocked {
		t.Fatalf("indirect cycle A->B->A should block")
	}
	if r.Reason != "fragment_cycle" {
		t.Errorf("expected reason=fragment_cycle, got %q", r.Reason)
	}
}

func TestGraphQL_V34_FragmentCycle_AcyclicAllowed(t *testing.T) {
	q := `
		query Q { user { ...A } }
		fragment A on User { id ...B }
		fragment B on User { name }
	`
	r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
	if r.Blocked {
		t.Fatalf("acyclic fragment graph should not block, reason=%s", r.Reason)
	}
}

func TestGraphQL_V34_FragmentCycle_NoFragmentsNoCycle(t *testing.T) {
	q := `query Q { user { id name } }`
	r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
	if r.Blocked {
		t.Fatalf("plain query with no fragments should not block")
	}
}

func TestGraphQL_V34_FragmentCycle_QueryOperationSpreadsDoNotPollute(t *testing.T) {
	// `...A` appears inside the query operation, not inside any fragment
	// body. With brace-matched extraction the spread should NOT be
	// attributed to fragment B's deps. Without brace matching, B's body
	// would extend into the query op and include `...A`, falsely flagging
	// a B->A->B cycle.
	q := `
		fragment B on User { name }
		query Q { user { ...A } ...B }
		fragment A on User { id ...B }
	`
	r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
	if r.Blocked {
		t.Fatalf("spreads inside query op should not pollute fragment deps; got reason=%s", r.Reason)
	}
}

func TestGraphQL_V34_FragmentCycle_DisableViaOption(t *testing.T) {
	opts := NewGraphqlGuardOptions()
	opts.BlockFragmentCycles = false
	q := `
		query Q { user { ...A } }
		fragment A on User { id ...A }
	`
	r := InspectGraphqlQuery(q, opts)
	if r.Blocked {
		t.Fatalf("with BlockFragmentCycles=false, cycle should not block; got reason=%s", r.Reason)
	}
}

// Precedence: depth > introspection > aliases > fragment_cycle > length.

func TestGraphQL_V34_Precedence_DepthBeatsAliases(t *testing.T) {
	var b strings.Builder
	// Build a deep + alias-heavy query. Depth should win.
	b.WriteString("query {")
	for i := 0; i < 15; i++ {
		b.WriteString(" x {")
	}
	for i := 0; i < 60; i++ {
		b.WriteString(" a")
		for d := i; d > 0; d /= 10 {
			b.WriteByte(byte('0' + d%10))
		}
		b.WriteString(": y")
	}
	for i := 0; i < 15; i++ {
		b.WriteString(" }")
	}
	b.WriteString(" }")
	r := InspectGraphqlQuery(b.String(), NewGraphqlGuardOptions())
	if !r.Blocked {
		t.Fatalf("expected blocked")
	}
	if r.Reason != "depth" {
		t.Errorf("expected reason=depth (highest precedence), got %q", r.Reason)
	}
}
