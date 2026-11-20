package dkim

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

// identityMatrixCase is a fixed matrix of DKIM signing identities. Rejected
// identities never reach the DNS layer, while accepted ones resolve to the
// QueryName passed to the TXT lookup.
type identityMatrixCase struct {
	name      string
	domain    string
	selector  string
	rejected  bool
	queryName string
}

var identityMatrix = []identityMatrixCase{
	{name: "valid", domain: "example.com", selector: "brisbane", rejected: false, queryName: "brisbane._domainkey.example.com"},
	{name: "valid uppercase and trailing dot", domain: "EXAMPLE.COM.", selector: "BrisBane.", rejected: false, queryName: "brisbane._domainkey.example.com"},
	{name: "domain empty label", domain: "example..com", selector: "brisbane", rejected: true},
	{name: "domain trailing empty label", domain: "example.com..", selector: "brisbane", rejected: true},
	{name: "domain control character", domain: "ex\x00ample.com", selector: "brisbane", rejected: true},
	{name: "domain newline injection", domain: "example.com\n.evil.org", selector: "brisbane", rejected: true},
	{name: "domain oversized label", domain: repeatByte('a', maxDNSLabelLength+1) + ".com", selector: "brisbane", rejected: true},
	{name: "selector empty", domain: "example.com", selector: "", rejected: true},
	{name: "selector empty label", domain: "example.com", selector: "bris..bane", rejected: true},
	{name: "selector control character", domain: "example.com", selector: "bris\x07bane", rejected: true},
	{name: "selector space", domain: "example.com", selector: "bris bane", rejected: true},
	{name: "selector too long", domain: "example.com", selector: repeatByte('a', maxDNSLabelLength+1), rejected: true},
}

// identitySignature builds a minimal signed header carrying the given d=/s=
// tags. All other tags are valid so that a well-formed identity reaches the
// DNS query step.
func identitySignature(domain, selector string) string {
	return "DKIM-Signature: v=1; a=rsa-sha256; s=" + selector + "; d=" + domain + ";\r\n" +
		" h=From; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
		" b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB;\r\n" +
		"From: Joe SixPack <joe@football.example.com>\r\n" +
		"\r\n" +
		"body\r\n"
}

func TestVerify_identityMatrix(t *testing.T) {
	previousQuery := queryMethods[QueryMethodDNSTXT]
	defer func() { queryMethods[QueryMethodDNSTXT] = previousQuery }()

	for _, test := range identityMatrix {
		t.Run(test.name, func(t *testing.T) {
			var queried string
			queryMethods[QueryMethodDNSTXT] = func(domain, selector string, txtLookup txtLookupFunc) (*queryResult, error) {
				name, err := dnsQueryName(domain, selector)
				if err != nil {
					return nil, permFailError("invalid signing identity: " + err.Error())
				}
				queried = name
				if record, ok := identityKeyRecords[name]; ok {
					return parsePublicKey(record)
				}
				return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
			}
			options := &VerifyOptions{}

			verifications, err := VerifyWithOptions(strings.NewReader(identitySignature(test.domain, test.selector)), options)
			if err != nil {
				t.Fatalf("VerifyWithOptions returned unexpected error: %v", err)
			}
			if len(verifications) != 1 {
				t.Fatalf("Expected exactly one verification, got %v", len(verifications))
			}

			verifErr := verifications[0].Err
			if test.rejected {
				if !IsPermFail(verifErr) {
					t.Fatalf("Expected permanent failure for d=%q s=%q, got: %v", test.domain, test.selector, verifErr)
				}
				if queried != "" {
					t.Fatalf("Rejected identity must not trigger a DNS query, got query for %q", queried)
				}
				return
			}

			if queried != test.queryName {
				t.Fatalf("Expected DNS query for %q, got %q", test.queryName, queried)
			}
			// The identity is valid; later verification steps may fail, but
			// the failure must not be an identity rejection.
			if IsPermFail(verifErr) && verifErr.Error() != "" {
				if strings.Contains(verifErr.Error(), "invalid domain") || strings.Contains(verifErr.Error(), "invalid selector") {
					t.Fatalf("Valid identity was rejected: %v", verifErr)
				}
			}
		})
	}
}

// identityKeyRecords maps the expected query targets to parseable public key
// records so accepted identities fail only on the (intentionally bogus)
// signature, not on the key lookup.
var identityKeyRecords = map[string]string{
	"brisbane._domainkey.example.com": dnsPublicKey,
}

func TestVerify_identityMatrixMetadata(t *testing.T) {
	// Guard against accidental edits shrinking the fixed matrix.
	if len(identityMatrix) < 10 {
		t.Fatalf("Expected at least 10 fixed identity cases, got %v", len(identityMatrix))
	}

	var rejected, accepted int
	for _, test := range identityMatrix {
		if test.rejected {
			rejected++
		} else {
			accepted++
			if test.queryName == "" {
				t.Errorf("Accepted case %q must declare its query target", test.name)
			}
		}
	}
	if rejected == 0 || accepted == 0 {
		t.Fatalf("Matrix must cover both rejections and accepted queries, got rejected=%v accepted=%v", rejected, accepted)
	}

	var keys []string
	for _, test := range identityMatrix {
		keys = append(keys, test.name)
	}
	wantKeys := []string{
		"valid",
		"valid uppercase and trailing dot",
		"domain empty label",
		"domain trailing empty label",
		"domain control character",
		"domain newline injection",
		"domain oversized label",
		"selector empty",
		"selector empty label",
		"selector control character",
		"selector space",
		"selector too long",
	}
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("Fixed matrix changed:\n got %v\nwant %v", keys, wantKeys)
	}
}
