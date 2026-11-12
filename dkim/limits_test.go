package dkim

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestVerify_maxHeaderSize(t *testing.T) {
	r := newMailStringReader(unsignedMailString)
	options := VerifyOptions{MaxHeaderSize: 64}

	_, err := VerifyWithOptions(r, &options)
	if !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("Expected ErrHeaderTooLarge, got %v", err)
	}
}

func TestVerify_maxHeaderFields(t *testing.T) {
	r := newMailStringReader(unsignedMailString)
	options := VerifyOptions{MaxHeaderFields: 2}

	_, err := VerifyWithOptions(r, &options)
	if !errors.Is(err, ErrTooManyHeaderFields) {
		t.Fatalf("Expected ErrTooManyHeaderFields, got %v", err)
	}
}

func TestVerify_maxMessageSize_bodyExceeded(t *testing.T) {
	signed := signTestMail(t)

	r := strings.NewReader(signed + strings.Repeat("x", 4096))
	options := VerifyOptions{MaxMessageSize: 1024}

	_, err := VerifyWithOptions(r, &options)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Expected ErrMessageTooLarge, got %v", err)
	}
}

func TestVerify_maxMessageSize_parallelGoroutinesDoNotLeak(t *testing.T) {
	r := strings.NewReader(verifiedEd25519MailString + strings.Repeat("x", 4096))
	options := VerifyOptions{MaxMessageSize: 2048}

	_, err := VerifyWithOptions(r, &options)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Expected ErrMessageTooLarge, got %v", err)
	}

	runtime.GC()
	// Give the verification goroutines time to notice the closed pipes.
	baseline := runtime.NumGoroutine()
	for i := 0; i < 100 && runtime.NumGoroutine() > baseline+2; i++ {
		runtime.Gosched()
	}
	if n := runtime.NumGoroutine(); n > baseline+2 {
		t.Fatalf("Verification goroutines leaked after body limit: %v > %v", n, baseline)
	}
}

func TestVerify_maxMessageSize_exactLimitAccepted(t *testing.T) {
	signed := signTestMail(t)

	r := strings.NewReader(signed)
	options := VerifyOptions{MaxMessageSize: int64(len(signed))}

	verifications, err := VerifyWithOptions(r, &options)
	if err != nil {
		t.Fatalf("Expected no error for a message exactly at the limit, got %v", err)
	}
	if len(verifications) != 1 {
		t.Fatalf("Expected exactly one verification, got %v", len(verifications))
	}
	if verifications[0].Err != nil {
		t.Fatalf("Expected signature to verify, got %v", verifications[0].Err)
	}
}

func TestVerify_limitsGenerous(t *testing.T) {
	signed := signTestMail(t)

	r := strings.NewReader(signed)
	options := VerifyOptions{
		MaxMessageSize:   1 << 20,
		MaxHeaderSize:    1 << 16,
		MaxHeaderFields:  100,
		MaxVerifications: 4,
	}

	verifications, err := VerifyWithOptions(r, &options)
	if err != nil {
		t.Fatalf("Expected no error with generous limits, got %v", err)
	}
	if len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("Expected one valid verification, got %+v", verifications)
	}
}

func TestVerify_insecureBodyLengthTagStillRejected(t *testing.T) {
	r := newMailStringReader(strings.Replace(verifiedMailString,
		"c=simple/simple; q=dns/txt;",
		"c=simple/simple; l=42; q=dns/txt;", 1))

	verifications, err := VerifyWithOptions(r, &VerifyOptions{})
	if err != nil {
		t.Fatalf("Expected no top-level error, got %v", err)
	}
	if len(verifications) != 1 {
		t.Fatalf("Expected exactly one verification, got %v", len(verifications))
	}
	if verifications[0].Err == nil ||
		!strings.Contains(verifications[0].Err.Error(), "insecure body length tag") {
		t.Fatalf("Expected insecure body length tag rejection, got %v", verifications[0].Err)
	}
}

func TestVerify_limitErrorsAreDistinguishable(t *testing.T) {
	limitErrors := []error{
		ErrTooManySignatures,
		ErrHeaderTooLarge,
		ErrTooManyHeaderFields,
		ErrMessageTooLarge,
	}
	seen := make(map[error]bool)
	for _, err := range limitErrors {
		if seen[err] {
			t.Fatalf("Duplicate limit error: %v", err)
		}
		seen[err] = true
	}
}

func signTestMail(t *testing.T) string {
	t.Helper()

	var b bytes.Buffer
	if err := Sign(&b, strings.NewReader(mailString), &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return b.String()
}
