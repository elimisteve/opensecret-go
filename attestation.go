package opensecret

import (
	"bytes"
	_ "embed"
	"encoding/base64"

	"github.com/hf/nitrite"
)

//go:embed assets/aws_nitro_root.der
var awsNitroRootCert []byte

// AttestationDocument represents a parsed attestation document
type AttestationDocument struct {
	ModuleID    string
	Timestamp   uint64
	Digest      string
	PCRs        map[uint][]byte
	Certificate []byte
	CABundle    [][]byte
	PublicKey   []byte
	UserData    []byte
	Nonce       []byte
}

// AttestationVerifier verifies AWS Nitro attestation documents. AllowDebug is
// the only mutable-after-construction state it carries — PCR policy
// (ExpectedPCRs / a validator callback) is deliberately NOT a field. An
// earlier version stored a PCRValidator field here, mutated per-handshake by
// callers wanting a fresh closure per call (e.g. one bound to that call's
// context); that is a data race on any *AttestationVerifier used from more
// than one goroutine, and even single-goroutine "set then immediately call"
// is not atomic against a second caller sharing the same client. PCR policy
// is now passed directly into VerifyAttestationDocument as ordinary
// parameters instead, which cannot race by construction (2026-08-15, review
// finding).
type AttestationVerifier struct {
	AllowDebug bool
}

// NewAttestationVerifier creates a new attestation verifier
func NewAttestationVerifier() *AttestationVerifier {
	return &AttestationVerifier{
		AllowDebug: false,
	}
}

// WithAllowDebug enables debug/mock mode
func (v *AttestationVerifier) WithAllowDebug(allow bool) *AttestationVerifier {
	v.AllowDebug = allow
	return v
}

// VerifyAttestationDocument verifies an attestation document and returns the
// parsed document. expectedPCRs and pcrValidator are both optional (nil
// skips that check) and are genuine per-call arguments, not stored state —
// concurrent calls on the same *AttestationVerifier, even with different
// policies, cannot race or clobber each other.
func (v *AttestationVerifier) VerifyAttestationDocument(documentB64 string, expectedNonce string, expectedPCRs map[uint][]byte, pcrValidator func(pcrs map[uint][]byte) error) (*AttestationDocument, error) {
	// Decode base64
	documentBytes, err := base64.StdEncoding.DecodeString(documentB64)
	if err != nil {
		return nil, NewAttestationError("failed to decode attestation document", err)
	}

	// Use nitrite to verify the attestation
	result, err := nitrite.Verify(documentBytes, nitrite.VerifyOptions{})
	if err != nil {
		return nil, NewAttestationError("attestation verification failed", err)
	}

	// Check signature
	if !result.SignatureOK {
		return nil, NewAttestationError("attestation signature verification failed", nil)
	}

	// Convert nitrite Document to our AttestationDocument
	doc := &AttestationDocument{
		ModuleID:    result.Document.ModuleID,
		Timestamp:   result.Document.Timestamp,
		Digest:      result.Document.Digest,
		PCRs:        result.Document.PCRs,
		Certificate: result.Document.Certificate,
		CABundle:    result.Document.CABundle,
		PublicKey:   result.Document.PublicKey,
		UserData:    result.Document.UserData,
		Nonce:       result.Document.Nonce,
	}

	// Verify nonce
	if len(doc.Nonce) == 0 {
		return nil, NewAttestationError("missing nonce in attestation document", nil)
	}

	nonceStr := string(doc.Nonce)
	if nonceStr != expectedNonce {
		return nil, NewAttestationError("nonce mismatch", nil)
	}

	// Verify PCRs if expected
	if expectedPCRs != nil {
		if err := verifyPCRs(doc, expectedPCRs); err != nil {
			return nil, err
		}
	}
	if pcrValidator != nil {
		if err := pcrValidator(doc.PCRs); err != nil {
			return nil, NewAttestationError("PCR validation failed", err)
		}
	}

	return doc, nil
}

func verifyPCRs(doc *AttestationDocument, expectedPCRs map[uint][]byte) error {
	for index, expected := range expectedPCRs {
		actual, ok := doc.PCRs[index]
		if !ok {
			return NewAttestationError("missing PCR", nil)
		}
		if !bytes.Equal(actual, expected) {
			return NewAttestationError("PCR mismatch", nil)
		}
	}
	return nil
}

// ParseMockAttestation extracts fields from a mock attestation document without full verification
// This is used for localhost/development mode
func ParseMockAttestation(documentB64 string) (*AttestationDocument, error) {
	// Decode base64
	documentBytes, err := base64.StdEncoding.DecodeString(documentB64)
	if err != nil {
		return nil, NewAttestationError("failed to decode attestation document", err)
	}

	// Try to verify, but we'll accept it even if verification fails for mock mode
	result, err := nitrite.Verify(documentBytes, nitrite.VerifyOptions{})
	if err != nil {
		// For mock mode, we'll still try to extract what we can
		// The mock server sends a simplified format
		return nil, NewAttestationError("failed to parse mock attestation", err)
	}

	return &AttestationDocument{
		ModuleID:    result.Document.ModuleID,
		Timestamp:   result.Document.Timestamp,
		Digest:      result.Document.Digest,
		PCRs:        result.Document.PCRs,
		Certificate: result.Document.Certificate,
		CABundle:    result.Document.CABundle,
		PublicKey:   result.Document.PublicKey,
		UserData:    result.Document.UserData,
		Nonce:       result.Document.Nonce,
	}, nil
}
