package srp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// GenerateKey generates the server's public key B
// B = (k*v + g^b) % N
// verifier - the client's verifier value stored on the server
// Returns server's public key B or error if generation fails
func (p *Params) GenerateKey(verifier []byte) ([]byte, error) {
	// Generate random private value b for the server
	// p.abLen is in bits, convert to bytes (rounding up)
	byteLen := (p.abLen + 7) / 8
	bBytes := make([]byte, byteLen)
	_, err := rand.Read(bBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private value: %w", err)
	}

	// Convert values to big.Int
	v := new(big.Int).SetBytes(verifier) // Client's verifier
	b := new(big.Int).SetBytes(bBytes)   // Server's private value
	k := p.k                             // Multiplier parameter
	g := p.g                             // Generator
	N := p.n                             // Large prime modulus

	// Calculate B = (k*v + g^b) % N
	B := new(big.Int)

	// Compute k*v
	kv := new(big.Int).Mul(k, v)

	// Compute g^b mod N
	gb := new(big.Int).Exp(g, b, N)

	// Compute B = (k*v + g^b) mod N
	B.Add(kv, gb)
	B.Mod(B, N)

	// RFC 5054: Server MUST abort if B % N = 0
	if B.BitLen() == 0 {
		return nil, errors.New("generated server public key B is zero - security violation")
	}

	return B.Bytes(), nil
}
