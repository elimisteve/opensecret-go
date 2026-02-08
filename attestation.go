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

// AttestationVerifier verifies AWS Nitro attestation documents
type AttestationVerifier struct {
	ExpectedPCRs map[uint][]byte
	AllowDebug   bool
}

// NewAttestationVerifier creates a new attestation verifier
func NewAttestationVerifier() *AttestationVerifier {
	return &AttestationVerifier{
		AllowDebug: false,
	}
}

// WithExpectedPCRs sets expected PCR values for verification
func (v *AttestationVerifier) WithExpectedPCRs(pcrs map[uint][]byte) *AttestationVerifier {
	v.ExpectedPCRs = pcrs
	return v
}

// WithAllowDebug enables debug/mock mode
func (v *AttestationVerifier) WithAllowDebug(allow bool) *AttestationVerifier {
	v.AllowDebug = allow
	return v
}

// VerifyAttestationDocument verifies an attestation document and returns the parsed document
func (v *AttestationVerifier) VerifyAttestationDocument(documentB64 string, expectedNonce string) (*AttestationDocument, error) {
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
	if v.ExpectedPCRs != nil {
		if err := v.verifyPCRs(doc); err != nil {
			return nil, err
		}
	}

	return doc, nil
}

func (v *AttestationVerifier) verifyPCRs(doc *AttestationDocument) error {
	for index, expected := range v.ExpectedPCRs {
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
