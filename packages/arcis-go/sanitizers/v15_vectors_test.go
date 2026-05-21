package sanitizers

import (
	"strings"
	"testing"
)

// ─── LDAP strict + wire ─────────────────────────────────────────────────

func TestDetectLdapInjectionStrict_AttackPatterns(t *testing.T) {
	attacks := []string{
		"*)(uid=*))(|(uid=*",
		"admin)(uid=*",
		"*)(&(uid=admin)",
		")(cn=*",
		"*) (cn=admin",
	}
	for _, payload := range attacks {
		if !DetectLdapInjectionStrict(payload) {
			t.Errorf("expected LDAP attack pattern to be detected: %q", payload)
		}
	}
}

func TestDetectLdapInjectionStrict_LegitimateInput(t *testing.T) {
	safe := []string{
		"john",
		"user@example.com",
		"call me (when you can)",
		"Acme (USA) Inc",
		"rule: a)b",
		"open-paren-(no-close",
	}
	for _, input := range safe {
		if DetectLdapInjectionStrict(input) {
			t.Errorf("false positive on legitimate input: %q", input)
		}
	}
}

func TestDetectLdapInjection_LooseStillWorks(t *testing.T) {
	// Backwards compat: existing broad detector still fires on any
	// LDAP filter special char.
	if !DetectLdapInjection("user(test)") {
		t.Error("expected loose detector to fire on parens")
	}
	if !DetectLdapInjection("user*admin") {
		t.Error("expected loose detector to fire on asterisk")
	}
}

func TestScanThreats_LdapClassifiesAsLdap(t *testing.T) {
	// The exact Raghav-pilot payload. Before the fix this returned
	// vector=command (caught by the command regex on `*`). After the
	// fix it returns vector=ldap.
	body := map[string]interface{}{
		"username": "*)(uid=*))(|(uid=*",
		"password": "any",
	}
	hit := ScanThreats(body)
	if hit == nil {
		t.Fatal("expected ScanThreats to return a hit on LDAP payload")
	}
	if hit.Vector != "ldap" {
		t.Errorf("expected vector=ldap, got %q", hit.Vector)
	}
}

func TestScanThreats_SafeParensDoNotTripLdap(t *testing.T) {
	// The whole reason ldap-strict exists: legitimate parens-containing
	// strings must NOT trigger LDAP. If this regresses, ldap-strict has
	// been broadened back to the false-positive pattern.
	for _, safe := range []string{
		"Acme (USA) Inc",
		"call me (when you can)",
		"rule: a)b",
		"func(arg)",
	} {
		hit := ScanThreats(safe)
		if hit != nil && hit.Vector == "ldap" {
			t.Errorf("false positive: %q -> vector=ldap", safe)
		}
	}
}

// ─── XPath ─────────────────────────────────────────────────────────────

func TestDetectXPathInjection_Attacks(t *testing.T) {
	attacks := []string{
		"' or '1'='1",
		`" or "1"="1`,
		") or (",
		"') or ('a'='a",
	}
	for _, payload := range attacks {
		if !DetectXPathInjection(payload) {
			t.Errorf("expected XPath injection to be detected: %q", payload)
		}
	}
}

func TestDetectXPathInjection_Safe(t *testing.T) {
	for _, safe := range []string{
		"john",
		"john@example.com",
		"O'Brien",          // apostrophe alone, no boolean
		"Title (subtitle)", // parens alone, no boolean
		"/path/to/node",
		"",
	} {
		if DetectXPathInjection(safe) {
			t.Errorf("false positive: %q", safe)
		}
	}
}

func TestSanitizeXPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"' or '1'='1", " or 1=1"},
		{"O'Brien", "OBrien"},
		{`foo"bar|baz,qux`, "foobarbazqux"},
		{"safe-input", "safe-input"},
	}
	for _, c := range cases {
		got := SanitizeXPath(c.in)
		if got != c.want {
			t.Errorf("SanitizeXPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Idempotence (Pattern 8).
	clean := SanitizeXPath("' or '1'='1")
	if SanitizeXPath(clean) != clean {
		t.Error("SanitizeXPath not idempotent")
	}
}

func TestScanThreats_XPathClassifiesAsXPath(t *testing.T) {
	// Function-arity tampering shape is uniquely XPath (NOT SQL).
	hit := ScanThreats("admin') or ('a'='a")
	if hit == nil {
		t.Fatal("expected ScanThreats to return a hit on XPath payload")
	}
	if hit.Vector != "xpath" {
		t.Errorf("expected vector=xpath, got %q", hit.Vector)
	}
}

func TestScanThreats_SqlBeforeXPathInOrdering(t *testing.T) {
	// Cross-SDK parity note: Go's current SQL detector doesn't match
	// the bare `1' OR '1'='1` shape that Python's does. Because of
	// this, the same payload classifies as 'xpath' in Go but 'sql' in
	// Python — a pre-existing Pattern 7 divergence the new XPath
	// detector surfaces. Worth fixing in a follow-up by aligning the
	// SQL regex across SDKs.
	//
	// For now, this test pins the ordering: WHEN a payload matches
	// BOTH SQL and XPath patterns, SQL wins. Use a payload Go's SQL
	// regex actually catches.
	hit := ScanThreats("' UNION SELECT password FROM users--")
	if hit == nil {
		t.Fatal("expected ScanThreats to return a hit")
	}
	if hit.Vector != "sql" {
		t.Errorf("expected vector=sql (UNION SELECT shape), got %q", hit.Vector)
	}
}

// ─── Email-header CRLF ─────────────────────────────────────────────────

func TestDetectEmailHeaderInjection_Attacks(t *testing.T) {
	attacks := []string{
		"victim@example.com\r\nBcc: attacker@evil.com",
		"user\nCc: leak@evil.com",
		"support@example.com\r\nFrom: admin@example.com",
		"name\r\nReply-To: attacker@evil.com",
		"x\r\nContent-Type: text/html",
	}
	for _, payload := range attacks {
		if !DetectEmailHeaderInjection(payload) {
			t.Errorf("expected email-header injection: %q", payload)
		}
	}
}

func TestDetectEmailHeaderInjection_Safe(t *testing.T) {
	for _, safe := range []string{
		"victim@example.com",
		"multi-line\ntext content",     // newline, no SMTP keyword
		"From this point on",            // 'From' word, no CRLF prefix
		"Subject of conversation today", // 'Subject' word, no CRLF prefix
		"",
	} {
		if DetectEmailHeaderInjection(safe) {
			t.Errorf("false positive: %q", safe)
		}
	}
}

func TestScanThreats_EmailHeaderClassifies(t *testing.T) {
	hit := ScanThreats("victim@example.com\r\nBcc: attacker@evil.com")
	if hit == nil || hit.Vector != "email-header" {
		t.Errorf("expected vector=email-header, got %+v", hit)
	}
}

// ─── GraphQL ───────────────────────────────────────────────────────────

func TestInspectGraphqlQuery_CleanQueries(t *testing.T) {
	clean := []string{
		"query { user { name } }",
		"query GetUser($id: ID!) { user(id: $id) { name email } }",
		"{ posts(first: 10) { edges { node { title author { name } } } } }",
		`mutation { createUser(input: {name: "jane"}) { id name } }`,
		"{ user { __typename name } }", // __typename allowed
	}
	for _, q := range clean {
		r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
		if r.Blocked {
			t.Errorf("legitimate query blocked: %q -> %s", q, r.Reason)
		}
	}
}

func TestInspectGraphqlQuery_DepthBomb(t *testing.T) {
	// 12 levels exceeds default of 10.
	q := "query { " + strings.Repeat("x { ", 11) + "x" + strings.Repeat(" }", 12)
	r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
	if !r.Blocked || r.Reason != "depth" {
		t.Errorf("expected depth block, got %+v", r)
	}
}

func TestInspectGraphqlQuery_Introspection(t *testing.T) {
	attacks := []string{
		"{ __schema { types { name } } }",
		`{ __type(name: "User") { fields { name } } }`,
		"{ __typeKind }",
		"{ __directive }",
	}
	for _, q := range attacks {
		r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
		if !r.Blocked || r.Reason != "introspection" {
			t.Errorf("expected introspection block on %q, got %+v", q, r)
		}
	}
}

func TestInspectGraphqlQuery_TypenameAllowed(t *testing.T) {
	// Apollo client uses __typename in every legit query. Catching it
	// would break every Apollo app on the first request.
	r := InspectGraphqlQuery(
		"{ user { __typename name } }", NewGraphqlGuardOptions(),
	)
	if r.Blocked {
		t.Errorf("__typename incorrectly blocked: %+v", r)
	}
}

func TestInspectGraphqlQuery_IntrospectionOptOut(t *testing.T) {
	opts := NewGraphqlGuardOptions()
	opts.BlockIntrospection = false
	r := InspectGraphqlQuery("{ __schema { types { name } } }", opts)
	if r.Blocked {
		t.Errorf("introspection block should be off, got %+v", r)
	}
}

func TestInspectGraphqlQuery_PrecedenceDepthBeatsIntrospection(t *testing.T) {
	// Both depth-bomb (>10) AND introspection.
	q := "query { __schema { " + strings.Repeat("x { ", 14) + "x" +
		strings.Repeat(" }", 15) + " } }"
	r := InspectGraphqlQuery(q, NewGraphqlGuardOptions())
	if !r.Blocked || r.Reason != "depth" {
		t.Errorf("expected depth precedence, got %+v", r)
	}
}

func TestInspectGraphqlQuery_UnbalancedBracesClampDepth(t *testing.T) {
	r := InspectGraphqlQuery("} } } }", NewGraphqlGuardOptions())
	if r.Depth != 0 {
		t.Errorf("expected depth=0 on unbalanced input, got %d", r.Depth)
	}
}

func TestInspectGraphqlQuery_UserDoubleUnderscorePasses(t *testing.T) {
	// \b__ anchor avoids false-matches on user fields like
	// last__updated_at, double__column.
	r := InspectGraphqlQuery(
		"{ user { last__updated_at } }", NewGraphqlGuardOptions(),
	)
	if r.Blocked {
		t.Errorf("user double-underscore field incorrectly blocked: %+v", r)
	}
}

func TestDetectGraphqlAbuse_BooleanAPI(t *testing.T) {
	if !DetectGraphqlAbuse("{ __schema { types { name } } }") {
		t.Error("expected introspection to be detected via DetectGraphqlAbuse")
	}
	if DetectGraphqlAbuse("query { user { name } }") {
		t.Error("clean query incorrectly flagged")
	}
	if DetectGraphqlAbuse("") {
		t.Error("empty query should return false")
	}
}

func TestZeroValueOptionsDoesNotBlockByDefault(t *testing.T) {
	// Documented quirk: passing GraphqlGuardOptions{} gives
	// BlockIntrospection=false because Go zero-value semantics.
	// Callers should use NewGraphqlGuardOptions() for documented defaults.
	r := InspectGraphqlQuery(
		"{ __schema { types { name } } }", GraphqlGuardOptions{},
	)
	if r.Blocked {
		t.Errorf("zero-value options: introspection should NOT be blocked, got %+v", r)
	}
}
