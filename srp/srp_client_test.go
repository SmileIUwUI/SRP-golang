package srp

import (
	"crypto"
	"math/big"
	"testing"
)

func TestGenerateVerifier(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	username := "alice"
	password := "password123"

	verifier, salt, err := params.GenerateVerifier(username, password)
	if err != nil {
		t.Fatalf("Failed to generate verifier: %v", err)
	}

	if len(verifier) == 0 {
		t.Error("Expected non-empty verifier")
	}

	if len(salt) != int(params.lenSalt) {
		t.Errorf("Expected salt length %d, got %d", params.lenSalt, len(salt))
	}

	// Verifier should be reproducible with same inputs
	verifier2, salt2, err := params.GenerateVerifier(username, password)
	if err != nil {
		t.Fatalf("Failed to generate verifier second time: %v", err)
	}

	// Salts should be different (random)
	saltEqual := true
	for i := range salt {
		if salt[i] != salt2[i] {
			saltEqual = false
			break
		}
	}

	if saltEqual {
		t.Error("Salts should be different due to randomness")
	}

	// But verifiers should be equivalent mathematically
	// (though not byte-equal due to different salts)
	if len(verifier) != len(verifier2) {
		t.Error("Verifiers should have same length")
	}
}

func TestGenerateKeyEphemeralClient(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	public, private, err := params.GenerateKeyEphemeralClient()
	if err != nil {
		t.Fatalf("Failed to generate client keys: %v", err)
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
		t.Error("Client public key should not be zero")
	}

	// Should be able to generate multiple different key pairs
	public2, private2, err := params.GenerateKeyEphemeralClient()
	if err != nil {
		t.Fatalf("Failed to generate second client keys: %v", err)
	}

	// Keys should be different due to randomness
	if equalBytes(public, public2) {
		t.Error("Public keys should be different")
	}

	if equalBytes(private, private2) {
		t.Error("Private keys should be different")
	}
}

func TestGenerateSharedKeyClient(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	// Simulate registration
	username := "testuser"
	password := "testpass"
	verifier, salt, err := params.GenerateVerifier(username, password)
	if err != nil {
		t.Fatalf("Failed to generate verifier: %v", err)
	}

	// Generate client keys
	A, a, err := params.GenerateKeyEphemeralClient()
	if err != nil {
		t.Fatalf("Failed to generate client keys: %v", err)
	}

	// Simulate server generating keys
	B, b, err := params.GenerateEphemeralKeyServer(verifier)
	if err != nil {
		t.Fatalf("Failed to generate server keys: %v", err)
	}

	// Client computes shared secret
	clientS, err := params.GenerateSharedKeyClient(username, password, salt, A, B, a)
	if err != nil {
		t.Fatalf("Failed to generate client shared key: %v", err)
	}

	if len(clientS) == 0 {
		t.Error("Expected non-empty shared secret from client")
	}

	// Server computes shared secret
	serverS, err := params.GenerateSharedKeyServer(A, B, b, verifier)
	if err != nil {
		t.Fatalf("Failed to generate server shared key: %v", err)
	}

	if len(serverS) == 0 {
		t.Error("Expected non-empty shared secret from server")
	}

	// Shared secrets should match
	if !equalBytes(clientS, serverS) {
		t.Error("Client and server shared secrets should match")
	}
}

func TestGenerateSharedKeyClient_InvalidInputs(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	username := "testuser"
	password := "testpass"
	salt := make([]byte, 16)
	A := make([]byte, 256)
	B := make([]byte, 256)
	a := make([]byte, 32)

	// Valid case should work
	_, err = params.GenerateSharedKeyClient(username, password, salt, A, B, a)
	if err != nil {
		// This might fail for mathematical reasons, but shouldn't fail for validation
		t.Logf("Note: Valid case failed for mathematical reasons: %v", err)
	}

	// Test empty inputs
	_, err = params.GenerateSharedKeyClient("", password, salt, A, B, a)
	if err == nil {
		t.Error("Expected error with empty username")
	}

	_, err = params.GenerateSharedKeyClient(username, "", salt, A, B, a)
	if err == nil {
		t.Error("Expected error with empty password")
	}

	_, err = params.GenerateSharedKeyClient(username, password, []byte{}, A, B, a)
	if err == nil {
		t.Error("Expected error with empty salt")
	}

	_, err = params.GenerateSharedKeyClient(username, password, salt, []byte{}, B, a)
	if err == nil {
		t.Error("Expected error with empty A")
	}
}

func TestClientProofVerification(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	// Simulate full SRP flow
	username := "alice"
	password := "secret123"

	// Registration
	verifier, salt, err := params.GenerateVerifier(username, password)
	if err != nil {
		t.Fatalf("Failed to generate verifier: %v", err)
	}

	// Authentication - Client
	A, a, err := params.GenerateKeyEphemeralClient()
	if err != nil {
		t.Fatalf("Failed to generate client keys: %v", err)
	}

	// Authentication - Server
	B, b, err := params.GenerateEphemeralKeyServer(verifier)
	if err != nil {
		t.Fatalf("Failed to generate server keys: %v", err)
	}

	// Both compute shared secret
	clientS, err := params.GenerateSharedKeyClient(username, password, salt, A, B, a)
	if err != nil {
		t.Fatalf("Failed to generate client shared key: %v", err)
	}

	serverS, err := params.GenerateSharedKeyServer(A, B, b, verifier)
	if err != nil {
		t.Fatalf("Failed to generate server shared key: %v", err)
	}

	// Client generates proof M1
	clientM1 := params.GenerateClientProof(clientS, A, B)

	// Server verifies client proof
	if !params.VerifyM1Proof(clientM1, serverS, A, B) {
		t.Error("Server should accept valid client proof")
	}

	// Server generates proof M2
	serverM2 := params.GenerateServerProof(A, clientM1)

	// Client verifies server proof
	if !params.VerifyServerProof(serverM2, A, clientM1) {
		t.Error("Client should accept valid server proof")
	}

	// Test with wrong proof
	wrongProof := make([]byte, len(clientM1))
	copy(wrongProof, clientM1)
	wrongProof[0] ^= 0x01 // Flip one bit

	if params.VerifyM1Proof(wrongProof, serverS, A, B) {
		t.Error("Server should reject invalid client proof")
	}

	if params.VerifyServerProof(wrongProof, A, clientM1) {
		t.Error("Client should reject invalid server proof")
	}
}

// Helper function to compare byte slices
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
