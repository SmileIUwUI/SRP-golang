package srp

import (
	"crypto"
	"testing"
)

// TestCompleteSRPFlow tests the complete SRP authentication flow
func TestCompleteSRPFlow(t *testing.T) {
	// Use different security levels and hash functions
	testCases := []struct {
		name     string
		secure   int16
		hashFunc crypto.Hash
	}{
		{"2048-SHA256", 2048, crypto.SHA256},
		{"3072-SHA512", 3072, crypto.SHA512},
		{"4096-SHA256", 4096, crypto.SHA256},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := NewParams(tc.secure, tc.hashFunc, 16)
			if err != nil {
				t.Fatalf("Failed to create params: %v", err)
			}

			username := "testuser"
			password := "testpassword"

			// === REGISTRATION PHASE ===
			verifier, salt, err := params.GenerateVerifier(username, password)
			if err != nil {
				t.Fatalf("Registration failed: %v", err)
			}

			// === AUTHENTICATION PHASE ===

			// Client: Generate ephemeral keys
			A, aPrivate, err := params.GenerateKeyEphemeralClient()
			if err != nil {
				t.Fatalf("Client key generation failed: %v", err)
			}

			// Server: Generate ephemeral keys using client's verifier
			B, bPrivate, err := params.GenerateEphemeralKeyServer(verifier)
			if err != nil {
				t.Fatalf("Server key generation failed: %v", err)
			}

			// Both parties compute shared secret
			clientSharedSecret, err := params.GenerateSharedKeyClient(username, password, salt, A, B, aPrivate)
			if err != nil {
				t.Fatalf("Client shared secret computation failed: %v", err)
			}

			serverSharedSecret, err := params.GenerateSharedKeyServer(A, B, bPrivate, verifier)
			if err != nil {
				t.Fatalf("Server shared secret computation failed: %v", err)
			}

			// Verify shared secrets match
			if !equalBytes(clientSharedSecret, serverSharedSecret) {
				t.Fatal("Shared secrets do not match")
			}

			// === PROOF EXCHANGE AND VERIFICATION ===

			// Client generates proof M1
			clientM1 := params.GenerateClientProof(clientSharedSecret, A, B)

			// Server verifies client's proof M1
			if !params.VerifyM1Proof(clientM1, serverSharedSecret, A, B) {
				t.Fatal("Server rejected valid client proof")
			}

			// Server generates proof M2
			serverM2 := params.GenerateServerProof(A, clientM1)

			// Client verifies server's proof M2
			if !params.VerifyServerProof(serverM2, A, clientM1) {
				t.Fatal("Client rejected valid server proof")
			}

			// === TEST SECURITY PROPERTIES ===

			// Test that different passwords produce different results
			wrongPassword := "wrongpassword"
			wrongSharedSecret, err := params.GenerateSharedKeyClient(username, wrongPassword, salt, A, B, aPrivate)
			if err == nil {
				if equalBytes(wrongSharedSecret, serverSharedSecret) {
					t.Error("Wrong password should not produce same shared secret")
				}
			}

			// Test proof verification fails with wrong data
			wrongM1 := make([]byte, len(clientM1))
			copy(wrongM1, clientM1)
			wrongM1[0] ^= 0x01

			if params.VerifyM1Proof(wrongM1, serverSharedSecret, A, B) {
				t.Error("Server should reject invalid client proof")
			}
		})
	}
}

// TestSRPWithDifferentHashFunctions tests SRP with various hash functions
func TestSRPWithDifferentHashFunctions(t *testing.T) {
	hashFunctions := []crypto.Hash{
		crypto.SHA1,
		crypto.SHA256,
		crypto.SHA512,
	}

	for _, hashFunc := range hashFunctions {
		if !hashFunc.Available() {
			continue
		}

		t.Run(hashFunc.String(), func(t *testing.T) {
			params, err := NewParams(2048, hashFunc, 16)
			if err != nil {
				t.Fatalf("Failed with %s: %v", hashFunc.String(), err)
			}

			username := "user"
			password := "pass"

			// Quick registration and authentication test
			verifier, salt, err := params.GenerateVerifier(username, password)
			if err != nil {
				t.Fatalf("Registration failed with %s: %v", hashFunc.String(), err)
			}

			A, a, err := params.GenerateKeyEphemeralClient()
			if err != nil {
				t.Fatalf("Client keys failed with %s: %v", hashFunc.String(), err)
			}

			B, b, err := params.GenerateEphemeralKeyServer(verifier)
			if err != nil {
				t.Fatalf("Server keys failed with %s: %v", hashFunc.String(), err)
			}

			clientS, err := params.GenerateSharedKeyClient(username, password, salt, A, B, a)
			if err != nil {
				t.Fatalf("Client shared secret failed with %s: %v", hashFunc.String(), err)
			}

			serverS, err := params.GenerateSharedKeyServer(A, B, b, verifier)
			if err != nil {
				t.Fatalf("Server shared secret failed with %s: %v", hashFunc.String(), err)
			}

			if !equalBytes(clientS, serverS) {
				t.Error("Shared secrets should match")
			}
		})
	}
}

// TestEdgeCases tests various edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	// Test with very long username and password
	longUsername := "very_long_username_that_exceeds_typical_length_restrictions_but_should_still_work"
	longPassword := "very_long_password_that_also_exceeds_typical_length_this_should_work_fine_in_srp_protocol"

	verifier, salt, err := params.GenerateVerifier(longUsername, longPassword)
	if err != nil {
		t.Fatalf("Failed with long credentials: %v", err)
	}

	A, a, err := params.GenerateKeyEphemeralClient()
	if err != nil {
		t.Fatalf("Failed to generate keys with long credentials: %v", err)
	}

	B, b, err := params.GenerateEphemeralKeyServer(verifier)
	if err != nil {
		t.Fatalf("Failed to generate server keys with long credentials: %v", err)
	}

	clientS, err := params.GenerateSharedKeyClient(longUsername, longPassword, salt, A, B, a)
	if err != nil {
		t.Fatalf("Failed to compute shared secret with long credentials: %v", err)
	}

	serverS, err := params.GenerateSharedKeyServer(A, B, b, verifier)
	if err != nil {
		t.Fatalf("Failed to compute server shared secret with long credentials: %v", err)
	}

	if !equalBytes(clientS, serverS) {
		t.Error("Shared secrets should match with long credentials")
	}
}

// BenchmarkSRPOperations benchmarks the performance of SRP operations
func BenchmarkSRPOperations(b *testing.B) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		b.Fatalf("Failed to create params: %v", err)
	}

	username := "benchuser"
	password := "benchpass"
	verifier, salt, err := params.GenerateVerifier(username, password)
	if err != nil {
		b.Fatalf("Failed to generate verifier: %v", err)
	}

	b.ResetTimer()

	b.Run("GenerateKeyEphemeralClient", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := params.GenerateKeyEphemeralClient()
			if err != nil {
				b.Fatalf("Failed to generate client keys: %v", err)
			}
		}
	})

	b.Run("GenerateEphemeralKeyServer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := params.GenerateEphemeralKeyServer(verifier)
			if err != nil {
				b.Fatalf("Failed to generate server keys: %v", err)
			}
		}
	})

	b.Run("GenerateSharedKeyClient", func(b *testing.B) {
		A, a, _ := params.GenerateKeyEphemeralClient()
		B, _, _ := params.GenerateEphemeralKeyServer(verifier)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := params.GenerateSharedKeyClient(username, password, salt, A, B, a)
			if err != nil {
				b.Fatalf("Failed to generate client shared key: %v", err)
			}
		}
	})

	b.Run("GenerateSharedKeyServer", func(b *testing.B) {
		A, _, _ := params.GenerateKeyEphemeralClient()
		B, bPrivate, _ := params.GenerateEphemeralKeyServer(verifier)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := params.GenerateSharedKeyServer(A, B, bPrivate, verifier)
			if err != nil {
				b.Fatalf("Failed to generate server shared key: %v", err)
			}
		}
	})
}
