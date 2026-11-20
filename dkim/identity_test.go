package dkim

import "testing"

func TestParseDomain(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{name: "simple", input: "example.com", want: "example.com", wantOK: true},
		{name: "uppercase preserved as lowercase", input: "Example.COM", want: "example.com", wantOK: true},
		{name: "trailing dot accepted", input: "example.com.", want: "example.com", wantOK: true},
		{name: "uppercase with trailing dot", input: "Example.COM.", want: "example.com", wantOK: true},
		{name: "empty", input: "", wantOK: false},
		{name: "empty label", input: "example..com", wantOK: false},
		{name: "leading dot", input: ".example.com", wantOK: false},
		{name: "double trailing dot", input: "example.com..", wantOK: false},
		{name: "control character", input: "ex\x00ample.com", wantOK: false},
		{name: "newline", input: "example.com\n", wantOK: false},
		{name: "space inside label", input: "exa mple.com", wantOK: false},
		{name: "backslash", input: `example\.com`, wantOK: false},
		{name: "oversized label", input: repeatByte('a', maxDNSLabelLength+1) + ".com", wantOK: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseDomain(test.input)
			if test.wantOK {
				if err != nil {
					t.Fatalf("parseDomain(%q): unexpected error: %v", test.input, err)
				}
				if got != test.want {
					t.Errorf("parseDomain(%q): got %q, want %q", test.input, got, test.want)
				}
			} else if err == nil {
				t.Fatalf("parseDomain(%q): expected error, got %q", test.input, got)
			}
		})
	}
}

func TestParseSelector(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{name: "simple", input: "brisbane", want: "brisbane", wantOK: true},
		{name: "uppercase normalized", input: "BrisBane", want: "brisbane", wantOK: true},
		{name: "underscore allowed", input: "dkim_2023", want: "dkim_2023", wantOK: true},
		{name: "dotted label", input: "selector.sub", want: "selector.sub", wantOK: true},
		{name: "trailing dot accepted", input: "brisbane.", want: "brisbane", wantOK: true},
		{name: "empty", input: "", wantOK: false},
		{name: "empty label", input: "sel..ector", wantOK: false},
		{name: "leading dot", input: ".selector", wantOK: false},
		{name: "control character", input: "sel\x07ector", wantOK: false},
		{name: "tab inside", input: "sel\tector", wantOK: false},
		{name: "space inside", input: "sel ector", wantOK: false},
		{name: "oversized selector", input: repeatByte('a', maxDNSLabelLength+1), wantOK: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseSelector(test.input)
			if test.wantOK {
				if err != nil {
					t.Fatalf("parseSelector(%q): unexpected error: %v", test.input, err)
				}
				if got != test.want {
					t.Errorf("parseSelector(%q): got %q, want %q", test.input, got, test.want)
				}
			} else if err == nil {
				t.Fatalf("parseSelector(%q): expected error, got %q", test.input, got)
			}
		})
	}
}

func TestDNSQueryName(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		selector string
		want     string
		wantOK   bool
	}{
		{name: "basic", domain: "example.com", selector: "brisbane", want: "brisbane._domainkey.example.com", wantOK: true},
		{name: "case and trailing dot", domain: "Example.COM.", selector: "BrisBane.", want: "brisbane._domainkey.example.com", wantOK: true},
		{name: "domain empty label", domain: "example..com", selector: "brisbane", wantOK: false},
		{name: "selector control char", domain: "example.com", selector: "bris\x00bane", wantOK: false},
		{name: "domain too long", domain: repeatByte('a', maxDNSNameLength+1), selector: "brisbane", wantOK: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := dnsQueryName(test.domain, test.selector)
			if test.wantOK {
				if err != nil {
					t.Fatalf("dnsQueryName(%q, %q): unexpected error: %v", test.domain, test.selector, err)
				}
				if got != test.want {
					t.Errorf("dnsQueryName(%q, %q): got %q, want %q", test.domain, test.selector, got, test.want)
				}
			} else if err == nil {
				t.Fatalf("dnsQueryName(%q, %q): expected error, got %q", test.domain, test.selector, got)
			}
		})
	}
}

func repeatByte(b byte, n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}
