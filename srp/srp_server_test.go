package srp

import (
	"crypto"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestGenerateEphemeralKeyServer(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	// Create a verifier first
	username := "testuser"
	password := "testpass"
	verifier, _, err := params.GenerateVerifier(username, password)
	if err != nil {
		t.Fatalf("Failed to generate verifier: %v", err)
	}

	public, private, err := params.GenerateEphemeralKeyServer(verifier)
	if err != nil {
		t.Fatalf("Failed to generate server keys: %v", err)
	}

	if len(public) == 0 {
		t.Error("Expected non-empty public key")
	}

	if len(private) == 0 {
		t.Error("Expected non-empty private key")
	}

	// Public key should be valid (not zero)
	publicInt := new(big.Int).SetBytes(public)
	if publicInt.Sign() == 0 {
		t.Error("Server public key should not be zero")
	}

	// Should be able to generate multiple different key pairs
	public2, private2, err := params.GenerateEphemeralKeyServer(verifier)
	if err != nil {
		t.Fatalf("Failed to generate second server keys: %v", err)
	}

	// Keys should be different due to randomness
	if equalBytes(public, public2) {
		t.Error("Public keys should be different")
	}

	if equalBytes(private, private2) {
		t.Error("Private keys should be different")
	}
}

func TestGenerateSharedKeyServer(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	// Full SRP flow test
	username := "bob"
	password := "securepassword"

	// Registration
	verifier, salt, err := params.GenerateVerifier(username, password)
	if err != nil {
		t.Fatalf("Failed to generate verifier: %v", err)
	}

	// Client keys
	A, a, err := params.GenerateKeyEphemeralClient()
	if err != nil {
		t.Fatalf("Failed to generate client keys: %v", err)
	}

	// Server keys
	B, b, err := params.GenerateEphemeralKeyServer(verifier)
	if err != nil {
		t.Fatalf("Failed to generate server keys: %v", err)
	}

	// Server computes shared secret
	serverS, err := params.GenerateSharedKeyServer(A, B, b, verifier)
	if err != nil {
		t.Fatalf("Failed to generate server shared key: %v", err)
	}

	if len(serverS) == 0 {
		t.Error("Expected non-empty shared secret from server")
	}

	// Client computes shared secret
	clientS, err := params.GenerateSharedKeyClient(username, password, salt, A, B, a)
	if err != nil {
		t.Fatalf("Failed to generate client shared key: %v", err)
	}

	// Shared secrets should match
	if !equalBytes(clientS, serverS) {
		t.Error("Client and server shared secrets should match")
	}
}

func TestGenerateSharedKeyServer_InvalidInputs(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	A := make([]byte, 256)
	B := make([]byte, 256)
	b := make([]byte, 32)
	verifier := make([]byte, 256)

	// Test empty inputs
	_, err = params.GenerateSharedKeyServer([]byte{}, B, b, verifier)
	if err == nil {
		t.Error("Expected error with empty A")
	}

	_, err = params.GenerateSharedKeyServer(A, []byte{}, b, verifier)
	if err == nil {
		t.Error("Expected error with empty B")
	}

	_, err = params.GenerateSharedKeyServer(A, B, []byte{}, verifier)
	if err == nil {
		t.Error("Expected error with empty b")
	}

	_, err = params.GenerateSharedKeyServer(A, B, b, []byte{})
	if err == nil {
		t.Error("Expected error with empty verifier")
	}
}

func TestVerifyM1Proof(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	// Create test data
	S := make([]byte, 32)
	rand.Read(S)
	A := make([]byte, 256)
	rand.Read(A)
	B := make([]byte, 256)
	rand.Read(B)

	// Generate valid proof
	validProof := params.generateM1Proof(S, A, B)

	// Test verification
	if !params.VerifyM1Proof(validProof, S, A, B) {
		t.Error("Should verify valid proof")
	}

	// Test with wrong shared secret
	wrongS := make([]byte, len(S))
	copy(wrongS, S)
	wrongS[0] ^= 0x01

	if params.VerifyM1Proof(validProof, wrongS, A, B) {
		t.Error("Should reject proof with wrong shared secret")
	}

	// Test with tampered proof
	tamperedProof := make([]byte, len(validProof))
	copy(tamperedProof, validProof)
	tamperedProof[0] ^= 0x01

	if params.VerifyM1Proof(tamperedProof, S, A, B) {
		t.Error("Should reject tampered proof")
	}

	// Test with completely wrong proof
	wrongProof := make([]byte, len(validProof))
	rand.Read(wrongProof)

	if params.VerifyM1Proof(wrongProof, S, A, B) {
		t.Error("Should reject random proof")
	}
}

func TestGenerateServerProof(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	A := make([]byte, 256)
	rand.Read(A)
	clientM1 := make([]byte, 32) // Typical hash length
	rand.Read(clientM1)

	proof := params.GenerateServerProof(A, clientM1)

	if len(proof) == 0 {
		t.Error("Server proof should not be empty")
	}

	// Proof should be deterministic
	proof2 := params.GenerateServerProof(A, clientM1)

	if !equalBytes(proof, proof2) {
		t.Error("Server proof should be deterministic")
	}

	// Different inputs should produce different proofs
	differentM1 := make([]byte, len(clientM1))
	copy(differentM1, clientM1)
	differentM1[0] ^= 0x01

	proof3 := params.GenerateServerProof(A, differentM1)

	if equalBytes(proof, proof3) {
		t.Error("Different M1 should produce different server proof")
	}
}
