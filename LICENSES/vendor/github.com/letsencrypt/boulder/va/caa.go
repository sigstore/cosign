package va

import (
	"context"
	"fmt"
	"strings"
	"sync"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"github.com/miekg/dns"
)

type caaParams struct {
	accountURIID     int64
	validationMethod string
}

func (va *ValidationAuthorityImpl) IsCAAValid(ctx context.Context, req *vapb.IsCAAValidRequest) (*vapb.IsCAAValidResponse, error) {
	acmeID := identifier.ACMEIdentifier{
		Type:  identifier.DNS,
		Value: req.Domain,
	}
	params := &caaParams{
		accountURIID:     req.AccountURIID,
		validationMethod: req.ValidationMethod,
	}
	if prob := va.checkCAA(ctx, acmeID, params); prob != nil {
		return &vapb.IsCAAValidResponse{
			Problem: &corepb.ProblemDetails{
				ProblemType: string(prob.Type),
				Detail:      fmt.Sprintf("While processing CAA for %s: %s", req.Domain, prob.Detail),
			},
		}, nil
	}
	return &vapb.IsCAAValidResponse{}, nil
}

// checkCAA performs a CAA lookup & validation for the provided identifier. If
// the CAA lookup & validation fail a problem is returned.
func (va *ValidationAuthorityImpl) checkCAA(
	ctx context.Context,
	identifier identifier.ACMEIdentifier,
	params *caaParams) *probs.ProblemDetails {
	present, valid, response, err := va.checkCAARecords(ctx, identifier, params)
	if err != nil {
		return probs.DNS(err.Error())
	}

	accountID, validationMethod := "unknown", "unknown"
	if params.accountURIID != 0 {
		accountID = fmt.Sprintf("%d", params.accountURIID)
	}
	if params.validationMethod != "" {
		validationMethod = params.validationMethod
	}

	va.log.AuditInfof("Checked CAA records for %s, [Present: %t, Account ID: %s, Challenge: %s, Valid for issuance: %t] Response=%q",
		identifier.Value, present, accountID, validationMethod, valid, response)
	if !valid {
		return probs.CAA(fmt.Sprintf("CAA record for %s prevents issuance", identifier.Value))
	}
	return nil
}

// CAASet consists of filtered CAA records
type CAASet struct {
	Issue     []*dns.CAA
	Issuewild []*dns.CAA
	Iodef     []*dns.CAA
	Unknown   []*dns.CAA
}

// returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet CAASet) criticalUnknown() bool {
	if len(caaSet.Unknown) > 0 {
		for _, caaRecord := range caaSet.Unknown {
			// The critical flag is the bit with significance 128. However, many CAA
			// record users have misinterpreted the RFC and concluded that the bit
			// with significance 1 is the critical bit. This is sufficiently
			// widespread that that bit must reasonably be considered an alias for
			// the critical bit. The remaining bits are 0/ignore as proscribed by the
			// RFC.
			if (caaRecord.Flag & (128 | 1)) != 0 {
				return true
			}
		}
	}

	return false
}

// Filter CAA records by property
func newCAASet(CAAs []*dns.CAA) *CAASet {
	var filtered CAASet

	for _, caaRecord := range CAAs {
		switch strings.ToLower(caaRecord.Tag) {
		case "issue":
			filtered.Issue = append(filtered.Issue, caaRecord)
		case "issuewild":
			filtered.Issuewild = append(filtered.Issuewild, caaRecord)
		case "iodef":
			filtered.Iodef = append(filtered.Iodef, caaRecord)
		default:
			filtered.Unknown = append(filtered.Unknown, caaRecord)
		}
	}

	return &filtered
}

type caaResult struct {
	records  []*dns.CAA
	response string
	err      error
}

func parseResults(results []caaResult) (*CAASet, string, error) {
	// Return first result
	for _, res := range results {
		if res.err != nil {
			return nil, "", res.err
		}
		if len(res.records) > 0 {
			return newCAASet(res.records), res.response, nil
		}
	}
	return nil, "", nil
}

func (va *ValidationAuthorityImpl) parallelCAALookup(ctx context.Context, name string) []caaResult {
	labels := strings.Split(name, ".")
	results := make([]caaResult, len(labels))
	var wg sync.WaitGroup

	for i := 0; i < len(labels); i++ {
		// Start the concurrent DNS lookup.
		wg.Add(1)
		go func(name string, r *caaResult) {
			r.records, r.response, r.err = va.dnsClient.LookupCAA(ctx, name)
			wg.Done()
		}(strings.Join(labels[i:], "."), &results[i])
	}

	wg.Wait()
	return results
}

func (va *ValidationAuthorityImpl) getCAASet(ctx context.Context, hostname string) (*CAASet, string, error) {
	hostname = strings.TrimRight(hostname, ".")

	// See RFC 6844 "Certification Authority Processing" for pseudocode, as
	// amended by https://www.rfc-editor.org/errata/eid5065.
	// Essentially: check CAA records for the FDQN to be issued, and all
	// parent domains.
	//
	// The lookups are performed in parallel in order to avoid timing out
	// the RPC call.
	//
	// We depend on our resolver to snap CNAME and DNAME records.
	results := va.parallelCAALookup(ctx, hostname)
	return parseResults(results)
}

// checkCAARecords fetches the CAA records for the given identifier and then
// validates them. If the identifier argument's value has a wildcard prefix then
// the prefix is stripped and validation will be performed against the base
// domain, honouring any issueWild CAA records encountered as appropriate.
// checkCAARecords returns four values: the first is a bool indicating whether
// CAA records were present after filtering for known/supported CAA tags. The
// second is a bool indicating whether issuance for the identifier is valid. The
// unmodified *dns.CAA records that were processed/filtered are returned as the
// third argument. Any  errors encountered are returned as the fourth return
// value (or nil).
func (va *ValidationAuthorityImpl) checkCAARecords(
	ctx context.Context,
	identifier identifier.ACMEIdentifier,
	params *caaParams) (bool, bool, string, error) {
	hostname := strings.ToLower(identifier.Value)
	// If this is a wildcard name, remove the prefix
	var wildcard bool
	if strings.HasPrefix(hostname, `*.`) {
		hostname = strings.TrimPrefix(identifier.Value, `*.`)
		wildcard = true
	}
	caaSet, response, err := va.getCAASet(ctx, hostname)
	if err != nil {
		return false, false, "", err
	}
	present, valid := va.validateCAASet(caaSet, wildcard, params)
	return present, valid, response, nil
}

func containsMethod(commaSeparatedMethods, method string) bool {
	for _, m := range strings.Split(commaSeparatedMethods, ",") {
		if method == m {
			return true
		}
	}
	return false
}

// validateCAASet checks a provided *CAASet. When the wildcard argument is true
// this means the CAASet's issueWild records must be validated as well. This
// function returns two booleans: the first indicates whether the CAASet was
// empty, the second indicates whether the CAASet is valid for issuance to
// proceed.
func (va *ValidationAuthorityImpl) validateCAASet(caaSet *CAASet, wildcard bool, params *caaParams) (present, valid bool) {
	if caaSet == nil {
		// No CAA records found, can issue
		va.metrics.caaCounter.WithLabelValues("no records").Inc()
		return false, true
	}

	if caaSet.criticalUnknown() {
		// Contains unknown critical directives
		va.metrics.caaCounter.WithLabelValues("record with unknown critical directive").Inc()
		return true, false
	}

	if len(caaSet.Issue) == 0 && !wildcard {
		// Although CAA records exist, none of them pertain to issuance in this case.
		// (e.g. there is only an issuewild directive, but we are checking for a
		// non-wildcard identifier, or there is only an iodef or non-critical unknown
		// directive.)
		va.metrics.caaCounter.WithLabelValues("no relevant records").Inc()
		return true, true
	}

	// Per RFC 6844 Section 5.3 "issueWild properties MUST be ignored when
	// processing a request for a domain that is not a wildcard domain" so we
	// default to checking the `caaSet.Issue` records and only check
	// `caaSet.Issuewild` when `wildcard` is true and there is >0 `Issuewild`
	// records.
	records := caaSet.Issue
	if wildcard && len(caaSet.Issuewild) > 0 {
		records = caaSet.Issuewild
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet.
	for _, caa := range records {
		caaIssuerDomain, caaParameters, caaValid := extractIssuerDomainAndParameters(caa)
		if !caaValid || caaIssuerDomain != va.issuerDomain {
			continue
		}

		if features.Enabled(features.CAAAccountURI) {
			// Check the accounturi CAA parameter as defined
			// in section 3 of the draft CAA ACME RFC:
			// https://tools.ietf.org/html/draft-ietf-acme-caa-04
			caaAccountURI, ok := caaParameters["accounturi"]
			if ok {
				if params.accountURIID == 0 {
					continue
				}
				if !checkAccountURI(caaAccountURI, va.accountURIPrefixes, params.accountURIID) {
					continue
				}
			}
		}
		if features.Enabled(features.CAAValidationMethods) {
			// Check the validationmethods CAA parameter as defined
			// in section 4 of the draft CAA ACME RFC:
			// https://tools.ietf.org/html/draft-ietf-acme-caa-04
			caaMethods, ok := caaParameters["validationmethods"]
			if ok {
				if params.validationMethod == "" {
					continue
				}
				if !containsMethod(caaMethods, params.validationMethod) {
					continue
				}
			}
		}

		va.metrics.caaCounter.WithLabelValues("authorized").Inc()
		return true, true
	}

	// The list of authorized issuers is non-empty, but we are not in it. Fail.
	va.metrics.caaCounter.WithLabelValues("unauthorized").Inc()
	return true, false
}

// checkAccountURI checks the specified full account URI against the
// given accountID and a list of valid prefixes.
func checkAccountURI(accountURI string, accountURIPrefixes []string, accountID int64) bool {
	for _, prefix := range accountURIPrefixes {
		if accountURI == fmt.Sprintf("%s%d", prefix, accountID) {
			return true
		}
	}
	return false
}

// extractIssuerDomainAndParameters extracts the domain and parameters (if any)
// from a issue/issuewild CAA record. This follows sections 5.2 and 5.3 of the
// RFC 6844bis draft (https://tools.ietf.org/html/draft-ietf-lamps-rfc6844bis-00),
// where all components are semi-colon separated. The domain name (which may be
// an empty string in the unsatisfiable case) and a tag-value map of parameters
// are returned, along with a bool indicating if the CAA record is valid.
func extractIssuerDomainAndParameters(caa *dns.CAA) (domain string, parameters map[string]string, valid bool) {
	isIssueSpace := func(r rune) bool {
		return r == '\t' || r == ' '
	}

	// Semi-colons (ASCII 0x3B) are prohibited from being specified in the
	// parameter tag or value, hence we can simply split on semi-colons.
	parts := strings.Split(caa.Value, ";")
	domain = strings.TrimFunc(parts[0], isIssueSpace)
	parameters = make(map[string]string)

	// Handle the case where a semi-colon is specified following the domain
	// but no parameters are given.
	if len(parts[1:]) == 1 && strings.TrimFunc(parts[1], isIssueSpace) == "" {
		return domain, parameters, true
	}

	for _, parameter := range parts[1:] {
		// A parameter tag cannot include equal signs (ASCII 0x3D),
		// however they are permitted in the value itself.
		tv := strings.SplitN(parameter, "=", 2)
		if len(tv) != 2 {
			return domain, nil, false
		}

		tag := strings.TrimFunc(tv[0], isIssueSpace)
		for _, r := range []rune(tag) {
			// ASCII alpha/digits.
			// tag = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
			if r < 0x30 || r > 0x39 && r < 0x41 || r > 0x5a && r < 0x61 || r > 0x7a {
				return domain, nil, false
			}
		}

		value := strings.TrimFunc(tv[1], isIssueSpace)
		for _, r := range []rune(value) {
			// ASCII without whitespace/semi-colons.
			// value = *(%x21-3A / %x3C-7E)
			if r < 0x21 || r > 0x3a && r < 0x3c || r > 0x7e {
				return domain, nil, false
			}
		}

		parameters[tag] = value
	}

	return domain, parameters, true
}
