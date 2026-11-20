package dkim

import (
	"errors"
	"strings"
	"unicode"
)

// Max DNS wire-name length, including the trailing root label (RFC 1035
// section 2.3.4).
const maxDNSNameLength = 255

// Max length of a single DNS label (RFC 1035 section 2.3.4).
const maxDNSLabelLength = 63

// ErrInvalidIdentity is returned when a DKIM domain (d=) or selector (s=)
// tag cannot be used to form a valid DNS name.
var ErrInvalidIdentity = errors.New("dkim: invalid signing identity")

// hasInnerWhitespace reports whether s contains any Unicode whitespace.
// DKIM tag values only tolerate folding whitespace that has already been
// trimmed by parseHeaderParams; any remaining whitespace would silently be
// stripped by stripWhitespace and change the signing identity.
func hasInnerWhitespace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// validIdentityRune reports whether r is allowed in a DKIM domain or
// selector label. The character set is the "atext" production of RFC 6376
// section 2.11: ASCII letters, digits and a set of safe separators. Control
// characters, whitespace, dots and other special characters are rejected
// instead of being silently accepted in a DNS query.
func validIdentityRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	}

	switch r {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
		return true
	}

	return false
}

// parseIdentityLabel validates a single domain or selector label and returns
// its lowercase form.
func parseIdentityLabel(label string) (string, error) {
	if len(label) == 0 {
		return "", ErrInvalidIdentity
	}
	if len(label) > maxDNSLabelLength {
		return "", ErrInvalidIdentity
	}

	lower := strings.ToLower(label)
	for _, r := range lower {
		if !validIdentityRune(r) {
			return "", ErrInvalidIdentity
		}
	}
	return lower, nil
}

// parseIdentity splits a DKIM domain (d=) or selector (s=) tag into its
// validated, lowercase labels. A single trailing dot (an FQDN) is accepted
// and removed so the value can be embedded in a query name without producing
// an empty label. Empty labels, control characters and other forbidden
// characters are rejected.
func parseIdentity(value string) ([]string, error) {
	if value == "" {
		return nil, ErrInvalidIdentity
	}

	fqdn := strings.HasSuffix(value, ".")
	if fqdn {
		value = value[:len(value)-1]
	}
	if value == "" || strings.HasSuffix(value, ".") || strings.HasPrefix(value, ".") {
		return nil, ErrInvalidIdentity
	}

	labels := strings.Split(value, ".")
	parsed := make([]string, 0, len(labels))
	for _, label := range labels {
		normalized, err := parseIdentityLabel(label)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, normalized)
	}
	return parsed, nil
}

// parseDomain validates the SDID in the d= tag and returns its strict,
// lowercase form suitable for identity comparison and DNS queries. The
// original letter case and any trailing dot remain valid inputs: case is
// normalized per RFC 6376 section 3.2 and the trailing dot is dropped.
func parseDomain(domain string) (string, error) {
	labels, err := parseIdentity(domain)
	if err != nil {
		return "", err
	}

	normalized := strings.Join(labels, ".")
	if len(normalized) > maxDNSNameLength {
		return "", ErrInvalidIdentity
	}
	return normalized, nil
}

// parseSelector validates the s= tag and returns its strict, lowercase form.
// Selectors share the domain-name syntax, so the resulting query label must
// fit in a single 63-octet DNS label.
func parseSelector(selector string) (string, error) {
	labels, err := parseIdentity(selector)
	if err != nil {
		return "", err
	}

	normalized := strings.Join(labels, ".")
	if len(normalized) > maxDNSLabelLength {
		return "", ErrInvalidIdentity
	}
	return normalized, nil
}

// dnsQueryName builds the DNS TXT query name for a validated selector and
// domain as specified by RFC 6376 section 3.6.2.2:
// selector._domainkey.domain.
func dnsQueryName(domain, selector string) (string, error) {
	normalizedDomain, err := parseDomain(domain)
	if err != nil {
		return "", err
	}
	normalizedSelector, err := parseSelector(selector)
	if err != nil {
		return "", err
	}

	name := normalizedSelector + "._domainkey." + normalizedDomain
	if len(name) > maxDNSNameLength {
		return "", ErrInvalidIdentity
	}
	return name, nil
}
