package va

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"

	blog "github.com/letsencrypt/boulder/log"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

// caaMockDNS implements the `dns.DNSClient` interface with a set of useful test
// answers for CAA queries.
type caaMockDNS struct{}

func (mock caaMockDNS) LookupTXT(_ context.Context, hostname string) ([]string, error) {
	return nil, nil
}

func (mock caaMockDNS) LookupHost(_ context.Context, hostname string) ([]net.IP, error) {
	ip := net.ParseIP("127.0.0.1")
	return []net.IP{ip}, nil
}

func (mock caaMockDNS) LookupCAA(_ context.Context, domain string) ([]*dns.CAA, string, error) {
	var results []*dns.CAA
	var record dns.CAA
	switch strings.TrimRight(domain, ".") {
	case "caa-timeout.com":
		return nil, "", fmt.Errorf("error")
	case "reserved.com":
		record.Tag = "issue"
		record.Value = "ca.com"
		results = append(results, &record)
	case "mixedcase.com":
		record.Tag = "iSsUe"
		record.Value = "ca.com"
		results = append(results, &record)
	case "critical.com":
		record.Flag = 1
		record.Tag = "issue"
		record.Value = "ca.com"
		results = append(results, &record)
	case "present.com", "present.servfail.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
	case "com":
		// com has no CAA records.
		return nil, "", nil
	case "servfail.com", "servfail.present.com":
		return results, "", fmt.Errorf("SERVFAIL")
	case "multi-crit-present.com":
		record.Flag = 1
		record.Tag = "issue"
		record.Value = "ca.com"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Value = "letsencrypt.org"
		results = append(results, &secondRecord)
	case "unknown-critical.com":
		record.Flag = 128
		record.Tag = "foo"
		record.Value = "bar"
		results = append(results, &record)
	case "unknown-critical2.com":
		record.Flag = 1
		record.Tag = "foo"
		record.Value = "bar"
		results = append(results, &record)
	case "unknown-noncritical.com":
		record.Flag = 0x7E // all bits we don't treat as meaning "critical"
		record.Tag = "foo"
		record.Value = "bar"
		results = append(results, &record)
	case "present-with-parameter.com":
		record.Tag = "issue"
		record.Value = "  letsencrypt.org  ;foo=bar;baz=bar"
		results = append(results, &record)
	case "present-with-invalid-tag.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; a_b=123"
		results = append(results, &record)
	case "present-with-invalid-value.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; ab=1 2 3"
		results = append(results, &record)
	case "present-dns-only.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; validationmethods=dns-01"
		results = append(results, &record)
	case "present-http-only.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; validationmethods=http-01"
		results = append(results, &record)
	case "present-http-or-dns.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; validationmethods=http-01,dns-01"
		results = append(results, &record)
	case "present-dns-only-correct-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/123; validationmethods=dns-01"
		results = append(results, &record)
	case "present-http-only-correct-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/123; validationmethods=http-01"
		results = append(results, &record)
	case "present-http-only-incorrect-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/321; validationmethods=http-01"
		results = append(results, &record)
	case "present-correct-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/123"
		results = append(results, &record)
	case "present-incorrect-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/321"
		results = append(results, &record)
	case "present-multiple-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/321"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issue"
		secondRecord.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/123"
		results = append(results, &secondRecord)
	case "unsatisfiable.com":
		record.Tag = "issue"
		record.Value = ";"
		results = append(results, &record)
	case "unsatisfiable-wildcard.com":
		// Forbidden issuance - issuewild doesn't contain LE
		record.Tag = "issuewild"
		record.Value = ";"
		results = append(results, &record)
	case "unsatisfiable-wildcard-override.com":
		// Forbidden issuance - issue allows LE, issuewild overrides and does not
		record.Tag = "issue"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issuewild"
		secondRecord.Value = "ca.com"
		results = append(results, &secondRecord)
	case "satisfiable-wildcard-override.com":
		// Ok issuance - issue doesn't allow LE, issuewild overrides and does
		record.Tag = "issue"
		record.Value = "ca.com"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issuewild"
		secondRecord.Value = "letsencrypt.org"
		results = append(results, &secondRecord)
	case "satisfiable-multi-wildcard.com":
		// Ok issuance - first issuewild doesn't permit LE but second does
		record.Tag = "issuewild"
		record.Value = "ca.com"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issuewild"
		secondRecord.Value = "letsencrypt.org"
		results = append(results, &secondRecord)
	case "satisfiable-wildcard.com":
		// Ok issuance - issuewild allows LE
		record.Tag = "issuewild"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
	}
	var response string
	if len(results) > 0 {
		response = "foo"
	}
	return results, response, nil
}

func TestCAATimeout(t *testing.T) {
	va, _ := setup(nil, 0, "", nil)
	va.dnsClient = caaMockDNS{}
	err := va.checkCAA(ctx, identifier.DNSIdentifier("caa-timeout.com"), nil)
	if err.Type != probs.DNSProblem {
		t.Errorf("Expected timeout error type %s, got %s", probs.DNSProblem, err.Type)
	}
	expected := "error"
	if err.Detail != expected {
		t.Errorf("checkCAA: got %#v, expected %#v", err.Detail, expected)
	}
}

func TestCAAChecking(t *testing.T) {
	testCases := []struct {
		Name    string
		Domain  string
		Present bool
		Valid   bool
	}{
		{
			Name:    "Bad (Reserved)",
			Domain:  "reserved.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (Reserved, Mixed case Issue)",
			Domain:  "mixedcase.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (Critical)",
			Domain:  "critical.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (NX Critical)",
			Domain:  "nx.critical.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Good (absent)",
			Domain:  "absent.com",
			Present: false,
			Valid:   true,
		},
		{
			Name:    "Good (example.co.uk, absent)",
			Domain:  "example.co.uk",
			Present: false,
			Valid:   true,
		},
		{
			Name:    "Good (present and valid)",
			Domain:  "present.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (present w/ servfail exception?)",
			Domain:  "present.servfail.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (multiple critical, one matching)",
			Domain:  "multi-crit-present.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Bad (unknown critical)",
			Domain:  "unknown-critical.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (unknown critical 2)",
			Domain:  "unknown-critical2.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Good (unknown non-critical, no issue/issuewild)",
			Domain:  "unknown-noncritical.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (issue rec with unknown params)",
			Domain:  "present-with-parameter.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Bad (issue rec with invalid tag)",
			Domain:  "present-with-invalid-tag.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (issue rec with invalid value)",
			Domain:  "present-with-invalid-value.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (restricts to dns-01, but tested with http-01)",
			Domain:  "present-dns-only.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Good (restricts to http-01, tested with http-01)",
			Domain:  "present-http-only.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (restricts to http-01 or dns-01, tested with http-01)",
			Domain:  "present-http-or-dns.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (restricts to accounturi, tested with correct account)",
			Domain:  "present-correct-accounturi.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (restricts to http-01 and accounturi, tested with correct account)",
			Domain:  "present-http-only-correct-accounturi.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Bad (restricts to dns-01 and accounturi, tested with http-01)",
			Domain:  "present-dns-only-correct-accounturi.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (restricts to http-01 and accounturi, tested with incorrect account)",
			Domain:  "present-http-only-incorrect-accounturi.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (restricts to accounturi, tested with incorrect account)",
			Domain:  "present-incorrect-accounturi.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Good (restricts to multiple accounturi, tested with a correct account)",
			Domain:  "present-multiple-accounturi.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Bad (unsatisfiable issue record)",
			Domain:  "unsatisfiable.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable issue, wildcard)",
			Domain:  "*.unsatisfiable.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable wildcard)",
			Domain:  "*.unsatisfiable-wildcard.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable wildcard override)",
			Domain:  "*.unsatisfiable-wildcard-override.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Good (satisfiable wildcard)",
			Domain:  "*.satisfiable-wildcard.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (multiple issuewild, one satisfiable)",
			Domain:  "*.satisfiable-multi-wildcard.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (satisfiable wildcard override)",
			Domain:  "*.satisfiable-wildcard-override.com",
			Present: true,
			Valid:   true,
		},
	}

	accountURIID := int64(123)
	method := "http-01"
	params := &caaParams{accountURIID: accountURIID, validationMethod: method}

	va, _ := setup(nil, 0, "", nil)
	err := features.Set(map[string]bool{"CAAValidationMethods": true, "CAAAccountURI": true})
	test.AssertNotError(t, err, "failed to enable features")

	va.dnsClient = caaMockDNS{}
	va.accountURIPrefixes = []string{"https://letsencrypt.org/acct/reg/"}
	for _, caaTest := range testCases {
		mockLog := va.log.(*blog.Mock)
		mockLog.Clear()
		t.Run(caaTest.Name, func(t *testing.T) {
			ident := identifier.DNSIdentifier(caaTest.Domain)
			present, valid, _, err := va.checkCAARecords(ctx, ident, params)
			if err != nil {
				t.Errorf("checkCAARecords error for %s: %s", caaTest.Domain, err)
			}
			if present != caaTest.Present {
				t.Errorf("checkCAARecords presence mismatch for %s: got %t expected %t", caaTest.Domain, present, caaTest.Present)
			}
			if valid != caaTest.Valid {
				t.Errorf("checkCAARecords validity mismatch for %s: got %t expected %t", caaTest.Domain, valid, caaTest.Valid)
			}
		})
	}

	// Reset to disable CAAValidationMethods/CAAAccountURI.
	features.Reset()

	// present-dns-only.com should now be valid even with http-01
	ident := identifier.DNSIdentifier("present-dns-only.com")
	present, valid, _, err := va.checkCAARecords(ctx, ident, params)
	test.AssertNotError(t, err, "present-dns-only.com")
	test.Assert(t, present, "Present should be true")
	test.Assert(t, valid, "Valid should be true")

	// present-incorrect-accounturi.com should now be also be valid
	ident = identifier.DNSIdentifier("present-incorrect-accounturi.com")
	present, valid, _, err = va.checkCAARecords(ctx, ident, params)
	test.AssertNotError(t, err, "present-incorrect-accounturi.com")
	test.Assert(t, present, "Present should be true")
	test.Assert(t, valid, "Valid should be true")

	// nil params should be valid, too
	present, valid, _, err = va.checkCAARecords(ctx, ident, nil)
	test.AssertNotError(t, err, "present-dns-only.com")
	test.Assert(t, present, "Present should be true")
	test.Assert(t, valid, "Valid should be true")

	ident.Value = "servfail.com"
	present, valid, _, err = va.checkCAARecords(ctx, ident, nil)
	test.AssertError(t, err, "servfail.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	if _, _, _, err := va.checkCAARecords(ctx, ident, nil); err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", ident.Value)
	}

	ident.Value = "servfail.present.com"
	present, valid, _, err = va.checkCAARecords(ctx, ident, nil)
	test.AssertError(t, err, "servfail.present.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	if _, _, _, err := va.checkCAARecords(ctx, ident, nil); err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", ident.Value)
	}
}

func TestCAALogging(t *testing.T) {
	va, _ := setup(nil, 0, "", nil)
	va.dnsClient = caaMockDNS{}

	testCases := []struct {
		Name            string
		Domain          string
		AccountURIID    int64
		ChallengeType   core.AcmeChallenge
		ExpectedLogline string
	}{
		{
			Domain:          "reserved.com",
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for reserved.com, [Present: true, Account ID: unknown, Challenge: unknown, Valid for issuance: false] Response=\"foo\"",
		},
		{
			Domain:          "reserved.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for reserved.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: false] Response=\"foo\"",
		},
		{
			Domain:          "reserved.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeDNS01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for reserved.com, [Present: true, Account ID: 12345, Challenge: dns-01, Valid for issuance: false] Response=\"foo\"",
		},
		{
			Domain:          "mixedcase.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for mixedcase.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: false] Response=\"foo\"",
		},
		{
			Domain:          "critical.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for critical.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: false] Response=\"foo\"",
		},
		{
			Domain:          "present.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for present.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: true] Response=\"foo\"",
		},
		{
			Domain:          "multi-crit-present.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for multi-crit-present.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: true] Response=\"foo\"",
		},
		{
			Domain:          "present-with-parameter.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for present-with-parameter.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: true] Response=\"foo\"",
		},
		{
			Domain:          "satisfiable-wildcard-override.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for satisfiable-wildcard-override.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: false] Response=\"foo\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Domain, func(t *testing.T) {
			mockLog := va.log.(*blog.Mock)
			mockLog.Clear()

			params := &caaParams{
				accountURIID:     tc.AccountURIID,
				validationMethod: string(tc.ChallengeType),
			}
			_ = va.checkCAA(ctx, identifier.ACMEIdentifier{Type: identifier.DNS, Value: tc.Domain}, params)

			caaLogLines := mockLog.GetAllMatching(`Checked CAA records for`)
			if len(caaLogLines) != 1 {
				t.Errorf("checkCAARecords didn't audit log CAA record info. Instead got:\n%s\n",
					strings.Join(mockLog.GetAllMatching(`.*`), "\n"))
			} else {
				test.AssertEquals(t, caaLogLines[0], tc.ExpectedLogline)
			}
		})
	}
}

// TestIsCAAValidErrMessage tests that an error result from `va.IsCAAValid`
// includes the domain name that was being checked in the failure detail.
func TestIsCAAValidErrMessage(t *testing.T) {
	va, _ := setup(nil, 0, "", nil)
	va.dnsClient = caaMockDNS{}

	// Call IsCAAValid with a domain we know fails with a generic error from the
	// caaMockDNS.
	domain := "caa-timeout.com"
	resp, err := va.IsCAAValid(ctx, &vapb.IsCAAValidRequest{
		Domain: domain,
	})

	// The lookup itself should not return an error
	test.AssertNotError(t, err, "Unexpected error calling IsCAAValidRequest")
	// The result should not be nil
	test.AssertNotNil(t, resp, "Response to IsCAAValidRequest was nil")
	// The result's Problem should not be nil
	test.AssertNotNil(t, resp.Problem, "Response Problem was nil")
	// The result's Problem should be an error message that includes the domain.
	test.AssertEquals(t, resp.Problem.Detail, fmt.Sprintf("While processing CAA for %s: error", domain))
}

func TestCAAFailure(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeHTTP01)
	hs := httpSrv(t, chall.Token)
	defer hs.Close()

	va, _ := setup(hs, 0, "", nil)
	va.dnsClient = caaMockDNS{}

	_, prob := va.validate(ctx, dnsi("reserved.com"), 0, chall)
	if prob == nil {
		t.Fatalf("Expected CAA rejection for reserved.com, got success")
	}
	test.AssertEquals(t, prob.Type, probs.CAAProblem)
}

func TestParseResults(t *testing.T) {
	// An empty slice of caaResults should return nil, "", nil
	r := []caaResult{}
	s, response, err := parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.Assert(t, err == nil, "error is not nil")
	test.Assert(t, response == "", "records is not nil")
	// A slice of empty caaResults should return nil, "", nil
	r = []caaResult{
		{[]*dns.CAA{}, "", nil},
		{[]*dns.CAA{}, "", nil},
		{[]*dns.CAA{}, "", nil},
	}
	s, response, err = parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.Assert(t, err == nil, "error is not nil")
	test.AssertEquals(t, response, "")
	// A slice of caaResults containing an error followed by a CAA
	// record should return the error
	r = []caaResult{
		{nil, "", errors.New("")},
		{[]*dns.CAA{{Value: "test"}}, "", nil},
	}
	s, response, err = parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertEquals(t, err.Error(), "")
	test.AssertEquals(t, response, "")
	//  A slice of caaResults containing a good record that precedes an
	//  error, should return that good record, not the error
	expected := dns.CAA{Value: "foo"}
	r = []caaResult{
		{[]*dns.CAA{&expected}, "foo", nil},
		{nil, "", errors.New("")},
	}
	s, response, err = parseResults(r)
	test.AssertEquals(t, len(s.Unknown), 1)
	test.Assert(t, s.Unknown[0] == &expected, "Incorrect record returned")
	test.AssertEquals(t, response, "foo")
	test.Assert(t, err == nil, "error is not nil")
	// A slice of caaResults containing multiple CAA records should
	// return the first non-empty CAA record
	r = []caaResult{
		{[]*dns.CAA{}, "", nil},
		{[]*dns.CAA{&expected}, "foo", nil},
		{[]*dns.CAA{{Value: "bar"}}, "bar", nil},
	}
	s, response, err = parseResults(r)
	test.AssertEquals(t, len(s.Unknown), 1)
	test.Assert(t, s.Unknown[0] == &expected, "Incorrect record returned")
	test.AssertEquals(t, response, "foo")
	test.AssertNotError(t, err, "no error should be returned")
}

func TestCheckAccountURI(t *testing.T) {
	tests := []struct {
		uri      string
		prefixes []string
		id       int64
		want     bool
	}{
		{
			uri: "https://acme-v01.api.letsencrypt.org/acme/reg/123456",
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
			},
			id:   123456,
			want: true,
		},
		{
			uri: "https://acme-v01.api.letsencrypt.org/acme/reg/123456",
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
			},
			id:   123457,
			want: false,
		},
		{
			uri: "https://acme-staging.api.letsencrypt.org/acme/reg/123456",
			prefixes: []string{
				"https://acme-staging.api.letsencrypt.org/acme/reg/",
				"https://acme-staging-v02.api.letsencrypt.org/acme/acct/",
			},
			id:   123456,
			want: true,
		},
		{
			uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
				"https://acme-v02.api.letsencrypt.org/acme/acct/",
			},
			id:   123456,
			want: true,
		},
		{
			uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
				"https://acme-v02.api.letsencrypt.org/acme/acct/",
				"https://acme-v03.api.letsencrypt.org/acme/acct/",
			},
			id:   123456,
			want: true,
		},
		{
			uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
				"https://acme-v02.api.letsencrypt.org/acme/acct/",
			},
			id:   654321,
			want: false,
		},
	}
	for _, test := range tests {
		if got, want := checkAccountURI(test.uri, test.prefixes, test.id), test.want; got != want {
			t.Errorf("checkAccountURI(%q, %v, %d) = %v, want %v", test.uri, test.prefixes, test.id, got, want)
		}
	}
}

func TestContainsMethod(t *testing.T) {
	test.AssertEquals(t, containsMethod("abc,123,xyz", "123"), true)
	test.AssertEquals(t, containsMethod("abc,xyz", "abc"), true)
	test.AssertEquals(t, containsMethod("abc,xyz", "xyz"), true)
	test.AssertEquals(t, containsMethod("abc", "abc"), true)

	test.AssertEquals(t, containsMethod("abc,xyz,123", "456"), false)
	test.AssertEquals(t, containsMethod("abc", "123"), false)
}

func TestExtractIssuerDomainAndParameters(t *testing.T) {
	tests := []struct {
		value          string
		wantDomain     string
		wantParameters map[string]string
		wantValid      bool
	}{
		{
			value:          "",
			wantDomain:     "",
			wantParameters: map[string]string{},
			wantValid:      true,
		},
		{
			value:          ";",
			wantDomain:     "",
			wantParameters: map[string]string{},
			wantValid:      true,
		},
		{
			value:          " ; ",
			wantDomain:     "",
			wantParameters: map[string]string{},
			wantValid:      true,
		},
		{
			value:          "letsencrypt.org",
			wantDomain:     "letsencrypt.org",
			wantParameters: map[string]string{},
			wantValid:      true,
		},
		{
			value:          "letsencrypt.org;",
			wantDomain:     "letsencrypt.org",
			wantParameters: map[string]string{},
			wantValid:      true,
		},
		{
			value: "  letsencrypt.org	;foo=bar;baz=bar",
			wantDomain:     "letsencrypt.org",
			wantParameters: map[string]string{"foo": "bar", "baz": "bar"},
			wantValid:      true,
		},
		{
			value: "	letsencrypt.org ;foo=bar;baz=bar",
			wantDomain:     "letsencrypt.org",
			wantParameters: map[string]string{"foo": "bar", "baz": "bar"},
			wantValid:      true,
		},
		{
			value: "letsencrypt.org; foo=; baz =	bar",
			wantDomain:     "letsencrypt.org",
			wantParameters: map[string]string{"foo": "", "baz": "bar"},
			wantValid:      true,
		},
		{
			value: "letsencrypt.org; foo=	; baz =	bar",
			wantDomain:     "letsencrypt.org",
			wantParameters: map[string]string{"foo": "", "baz": "bar"},
			wantValid:      true,
		},
		{
			value: "letsencrypt.org; foo=b1,b2,b3	; baz =		a=b	",
			wantDomain:     "letsencrypt.org",
			wantParameters: map[string]string{"foo": "b1,b2,b3", "baz": "a=b"},
			wantValid:      true,
		},
		{
			value: "letsencrypt.org; foo=b1,b2,b3	; baz =		a = b	",
			wantDomain: "letsencrypt.org",
			wantValid:  false,
		},
		{
			value: "letsencrypt.org; foo=b1,b2,b3	; baz=a=	b",
			wantDomain: "letsencrypt.org",
			wantValid:  false,
		},
		{
			value: "letsencrypt.org; foo=b1,b2,b3	; baz =		a;b	",
			wantDomain: "letsencrypt.org",
			wantValid:  false,
		},
		{
			value:          "letsencrypt.org; 1=2; baz=a-b",
			wantDomain:     "letsencrypt.org",
			wantParameters: map[string]string{"1": "2", "baz": "a-b"},
			wantValid:      true,
		},
		{
			value:      "letsencrypt.org; a_b=123",
			wantDomain: "letsencrypt.org",
			wantValid:  false,
		},
		{
			value:      "letsencrypt.org; ab=1 2 3",
			wantDomain: "letsencrypt.org",
			wantValid:  false,
		},
		{
			value:      "letsencrypt.org; 1=2; a-b=c",
			wantDomain: "letsencrypt.org",
			wantValid:  false,
		},
		{
			value:      "letsencrypt.org; foo=a\u2615b",
			wantDomain: "letsencrypt.org",
			wantValid:  false,
		},
		{
			value:      "letsencrypt.org; foo=b1,b2,b3 baz=a",
			wantDomain: "letsencrypt.org",
			wantValid:  false,
		},
	}
	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			caa := &dns.CAA{Value: test.value}
			gotDomain, gotParameters, gotValid := extractIssuerDomainAndParameters(caa)
			if got, want := gotValid, test.wantValid; got != want {
				t.Errorf("CAA value %q - got valid %v, want %v", test.value, got, want)
			}
			if got, want := gotDomain, test.wantDomain; got != want {
				t.Errorf("CAA value %q - got domain %q, want %q", test.value, got, want)
			}
			if got, want := gotParameters, test.wantParameters; !reflect.DeepEqual(got, want) {
				t.Errorf("CAA value %q - got parameters %v, want %v", test.value, got, want)
			}
		})
	}
}
