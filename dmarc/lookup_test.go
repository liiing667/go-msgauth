package dmarc

import (
	"testing"
	"time"
)

var parseTests = []struct {
	name string
	txt  string
	rec  *Record
	err  bool
}{
	{
		name: "compatible: minimal valid record",
		txt:  "v=DMARC1; p=none",
		rec: &Record{
			Policy:        PolicyNone,
			DKIMAlignment: AlignmentRelaxed,
			SPFAlignment:  AlignmentRelaxed,
		},
	},
	{
		name: "compatible: full valid legacy record",
		txt:  "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; fo=1:d; pct=50; rf=afrf; ri=86400; rua=mailto:agg@example.org; ruf=mailto:fail@example.org",
		rec: &Record{
			DKIMAlignment:      AlignmentStrict,
			SPFAlignment:       AlignmentStrict,
			FailureOptions:     FailureAny | FailureDKIM,
			Policy:             PolicyReject,
			Percent:            intPtr(50),
			ReportFormat:       []ReportFormat{ReportFormatAFRF},
			ReportInterval:     86400 * time.Second,
			ReportURIAggregate: []string{"mailto:agg@example.org"},
			ReportURIFailure:   []string{"mailto:fail@example.org"},
			SubdomainPolicy:    PolicyQuarantine,
		},
	},
	{
		name: "duplicate: identical p tag is rejected",
		txt:  "v=DMARC1; p=reject; p=reject",
		err:  true,
	},
	{
		name: "conflicting: later p overrides reject with none",
		txt:  "v=DMARC1; p=reject; p=none",
		err:  true,
	},
	{
		name: "conflicting: later p overrides none with reject",
		txt:  "v=DMARC1; p=none; p=reject",
		err:  true,
	},
	{
		name: "duplicate: repeated non-policy tag is rejected",
		txt:  "v=DMARC1; p=none; ruf=mailto:a@example.org; ruf=mailto:b@example.org",
		err:  true,
	},
	{
		name: "duplicate: repeated version tag is rejected",
		txt:  "v=DMARC1; v=DMARC1; p=none",
		err:  true,
	},
	{
		name: "malformed: pair without value",
		txt:  "v=DMARC1; p",
		err:  true,
	},
}

func intPtr(i int) *int {
	return &i
}

func TestParse(t *testing.T) {
	for _, tc := range parseTests {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := Parse(tc.txt)
			if tc.err {
				if err == nil {
					t.Fatalf("Parse(%q) = %+v, want error", tc.txt, rec)
				}
				if rec != nil {
					t.Fatalf("Parse(%q) returned non-nil record %+v with error %v", tc.txt, rec, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) = %v, want record %+v", tc.txt, err, tc.rec)
			}
			if !recordsEqual(rec, tc.rec) {
				t.Fatalf("Parse(%q) = %+v, want %+v", tc.txt, rec, tc.rec)
			}
		})
	}
}

func recordsEqual(got, want *Record) bool {
	if got.Policy != want.Policy ||
		got.SubdomainPolicy != want.SubdomainPolicy ||
		got.DKIMAlignment != want.DKIMAlignment ||
		got.SPFAlignment != want.SPFAlignment ||
		got.FailureOptions != want.FailureOptions ||
		got.ReportInterval != want.ReportInterval {
		return false
	}
	if (got.Percent == nil) != (want.Percent == nil) {
		return false
	}
	if got.Percent != nil && *got.Percent != *want.Percent {
		return false
	}
	return equalStrings(got.ReportFormat, want.ReportFormat) &&
		equalStrings(got.ReportURIAggregate, want.ReportURIAggregate) &&
		equalStrings(got.ReportURIFailure, want.ReportURIFailure)
}

func equalStrings[T ~string](got, want []T) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestLookupWithOptionsRejectsDuplicatePolicy(t *testing.T) {
	txts := []string{"v=DMARC1; p=reject; p=none"}
	options := &LookupOptions{
		LookupTXT: func(domain string) ([]string, error) {
			if domain != "_dmarc.example.org" {
				t.Fatalf("unexpected lookup domain %q", domain)
			}
			return txts, nil
		},
	}

	rec, err := LookupWithOptions("example.org", options)
	if err == nil {
		t.Fatalf("LookupWithOptions returned record %+v for duplicate policy tag, want error", rec)
	}
	if rec != nil {
		t.Fatalf("LookupWithOptions returned non-nil record %+v with error %v", rec, err)
	}
}

func TestLookupWithOptionsAcceptsLegacyRecord(t *testing.T) {
	options := &LookupOptions{
		LookupTXT: func(domain string) ([]string, error) {
			return []string{
				"not a dmarc record",
				"v=DMARC1; p=quarantine; rua=mailto:reports@example.org",
			}, nil
		},
	}

	rec, err := LookupWithOptions("example.org", options)
	if err != nil {
		t.Fatalf("LookupWithOptions failed for valid legacy record: %v", err)
	}
	if rec.Policy != PolicyQuarantine {
		t.Fatalf("Policy = %q, want %q", rec.Policy, PolicyQuarantine)
	}
	if len(rec.ReportURIAggregate) != 1 || rec.ReportURIAggregate[0] != "mailto:reports@example.org" {
		t.Fatalf("ReportURIAggregate = %v, want mailto:reports@example.org", rec.ReportURIAggregate)
	}
}
