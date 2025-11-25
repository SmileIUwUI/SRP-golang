package srp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// GenerateVerifier generates a salt and verifier for SRP registration
// The process follows: x = H(salt | H(username | ":" | password))
// verifier = g^x mod N
// Returns salt, verifier as hex strings, and any error encountered
func (p *Params) GenerateVerifier(username string, password string) ([]byte, []byte, error) {
	// Compute H(username | ":" | password)
	dataHash := p.hashFunc.New()
	dataHash.Write([]byte(username))
	dataHash.Write([]byte(":"))
	dataHash.Write([]byte(password))
	userPassHash := dataHash.Sum(nil)

	// Generate cryptographically secure random salt
	salt := make([]byte, p.lenSalt)
	_, err := rand.Read(salt)
	if err != nil {
		return []byte(""), []byte(""), err
	}

	// Compute x = H(salt | H(username | ":" | password))
	xHash := p.hashFunc.New()
	xHash.Write(salt)
	xHash.Write(userPassHash)
	xBytes := xHash.Sum(nil)

	// Convert hash output to a big integer
	x := new(big.Int).SetBytes(xBytes)

	// Compute verifier: v = g^x mod N
	v := new(big.Int).Exp(p.g, x, p.n)

	// Encode to hexadecimal strings for storage/transmission

	return salt, v.Bytes(), nil
}

// GenerateKeyClient generates client's key pair for SRP authentication
// Returns:
//   - clientPublic (A) - client's public key A = g^a mod N
//   - clientPrivate (a) - client's private ephemeral value
//   - error if any operation fails
func (p *Params) GenerateKeyClient() ([]byte, []byte, error) {
	// Generate client's private ephemeral value a with sufficient entropy
	byteLen := (p.abLen + 7) / 8 // Convert bits to bytes (rounding up)
	aBytes := make([]byte, byteLen)
	_, err := rand.Read(aBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate client private value: %w", err)
	}

	// Convert to big.Int for mathematical operations
	a := new(big.Int).SetBytes(aBytes)

	// Calculate client's public key A = g^a mod N
	A := new(big.Int).Exp(p.g, a, p.n)

	// RFC 5054: Server MUST abort if A % N = 0
	// This is a critical security check to prevent certain attacks
	if A.BitLen() == 0 {
		return nil, nil, errors.New("generated client public key A is zero - security violation")
	}

	return A.Bytes(), aBytes, nil
}
