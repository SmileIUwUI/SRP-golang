package srp

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

// GenerateKeyServer generates server's key pair for SRP authentication
// verifier - client's verifier (v) from registration
// Returns:
//   - serverPublic (B) - server's public key
//   - serverPrivate (b) - server's private ephemeral value
//   - error if any operation fails
func (p *Params) GenerateEphemeralKeyServer(verifier []byte) ([]byte, []byte, error) {
	// Generate server's private ephemeral value b
	byteLen := (p.abLen + 7) / 8 // Convert bits to bytes (rounding up)
	bBytes := make([]byte, byteLen)
	_, err := rand.Read(bBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server private value: %w", err)
	}

	// Convert input values to big.Int for mathematical operations
	v := new(big.Int).SetBytes(verifier) // Client's verifier v = g^x mod N
	b := new(big.Int).SetBytes(bBytes)   // Server's private ephemeral value
	k := p.k                             // Multiplier parameter k = H(N | G)
	g := p.g                             // Generator
	N := p.n                             // Large safe prime modulus

	// Calculate server's public key B = (k*v + g^b) % N
	B := new(big.Int)

	// Compute k * v mod N
	kv := new(big.Int).Mul(k, v)
	kv.Mod(kv, N) // Reduce intermediate result modulo N

	// Compute g^b mod N
	gb := new(big.Int).Exp(g, b, N)

	// Compute B = (k*v + g^b) mod N
	B.Add(kv, gb)
	B.Mod(B, N)

	// RFC 5054: Server MUST abort if B % N = 0
	// This prevents certain attacks and ensures protocol security
	if B.BitLen() == 0 {
		return nil, nil, errors.New("generated server public key B is zero - security violation")
	}

	// Return server's public key and private value as byte slices
	return B.Bytes(), bBytes, nil
}

// GenerateSharedKeyServer computes the server's shared session key
// using the formula: S = (A * v^u) ^ b mod N
// ABytes - client's public ephemeral value A
// BBytes - server's public ephemeral value B
// bBytes - server's private ephemeral value b
// verifierBytes - client's verifier v = g^x mod N
// Returns the shared secret S or error if validation fails
func (p *Params) GenerateSharedKeyServer(ABytes []byte, BBytes []byte, bBytes []byte, verifierBytes []byte) ([]byte, error) {
	// Validate that all required input parameters are provided
	if len(ABytes) == 0 || len(BBytes) == 0 || len(bBytes) == 0 || len(verifierBytes) == 0 {
		return nil, errors.New("invalid input parameters: all parameters must be non-empty")
	}

	// Calculate the scrambling parameter u = H(PAD(A) | PAD(B))
	// u is computed by hashing the padded representations of A and B
	nLength := len(p.n.Bytes())
	uHash := p.hashFunc.New()
	uHash.Write(padToLength(ABytes, nLength))
	uHash.Write(padToLength(BBytes, nLength))
	u := new(big.Int).SetBytes(uHash.Sum(nil))

	// Convert byte slices to big.Int for mathematical operations
	A := new(big.Int).SetBytes(ABytes)        // A = g^a mod N (from client)
	b := new(big.Int).SetBytes(bBytes)        // Server's private ephemeral value
	v := new(big.Int).SetBytes(verifierBytes) // v = g^x mod N (client's verifier)

	// RFC 5054 security validation: A must not be 0 and must be less than N
	if A.Sign() == 0 {
		return nil, errors.New("client public value A cannot be zero")
	}
	if A.Cmp(p.n) >= 0 {
		return nil, errors.New("client public value A must be less than N")
	}

	// Compute shared secret using server formula: S = (A * v^u) ^ b mod N

	// Step 1: Compute v^u mod N
	vu := new(big.Int).Exp(v, u, p.n)

	// Step 2: Compute A * v^u mod N
	Avu := new(big.Int).Mul(A, vu)
	Avu.Mod(Avu, p.n)

	// Step 3: Compute S = (A * v^u) ^ b mod N
	S := new(big.Int).Exp(Avu, b, p.n)

	// Additional security check: ensure shared secret is not zero
	if S.Sign() == 0 {
		return nil, errors.New("computed shared secret cannot be zero")
	}

	return S.Bytes(), nil
}

// VerifyM1Proof verifies the client's key confirmation proof M1
// Uses constant-time comparison to prevent timing attacks
//
// Parameters:
//
//	receivedM1 - the M1 proof received from the client
//	SBytes - shared secret S (session key) computed by server
//	ABytes - client's public ephemeral value A
//	BBytes - server's public ephemeral value B
//
// Returns:
//
//	bool - true if client proof is valid, false otherwise
func (p *Params) VerifyM1Proof(receivedM1 []byte, SBytes []byte, ABytes []byte, BBytes []byte) bool {
	// Generate expected M1 proof using the same parameters
	expectedM1 := p.generateM1Proof(SBytes, ABytes, BBytes)

	// Compare proofs using constant-time comparison
	// This prevents timing attacks that could reveal information about the proof
	return subtle.ConstantTimeCompare(receivedM1, expectedM1) == 1
}
