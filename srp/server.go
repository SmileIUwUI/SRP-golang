package srp

import (
	"crypto/rand"
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
func (p *Params) GenerateKeyServer(verifier []byte) ([]byte, []byte, error) {
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
