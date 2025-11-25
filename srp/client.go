package srp

import (
	"crypto/rand"
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
