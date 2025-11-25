package srp

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// Params represents SRP protocol parameters
// n - large safe prime number
// g - generator modulo n
// k - multiplier parameter
// hashFunc - cryptographic hash function to use
// lenSalt - length of salt in bytes
type Params struct {
	n        *big.Int
	g        *big.Int
	k        *big.Int
	abLen    int
	hashFunc crypto.Hash
	lenSalt  int16
}

// NewParams creates new SRP parameters with specified security level
// secure - bit size of the prime (2048, 3072, 4096, 6144, 8192)
// hashFunc - hash function to use (crypto.SHA1, crypto.SHA256, etc.)
// lenSalt - salt length in bytes (minimum 8 recommended)
// Returns configured SRP parameters or error if validation fails
func NewParams(secure int16, hashFunc crypto.Hash, lenSalt int16) (*Params, error) {
	// Ensure hash function implementations are linked by using them
	// This prevents "hash function not available" errors in some environments
	_ = md5.New()
	_ = sha1.New()
	_ = sha256.New()
	_ = sha512.New()

	// Validate salt length - minimum 8 bytes for security
	if lenSalt < 8 {
		return nil, errors.New("salt length must be at least 8 bytes")
	}

	// Check if the requested hash function is available in the current environment
	if !hashFunc.Available() {
		return nil, errors.New("requested hash function is not available")
	}

	var N, G *big.Int
	var abLen int

	// Select predefined N and G values based on security level
	// These are standard SRP group parameters from RFC 5054
	switch secure {
	case 2048:
		N = N_2048
		G = G_2048
		abLen = ab_2048_len
	case 3072:
		N = N_3072
		G = G_3072
		abLen = ab_3072_len
	case 4096:
		N = N_4096
		G = G_4096
		abLen = ab_4096_len
	case 6144:
		N = N_6144
		G = G_6144
		abLen = ab_6144_len
	case 8192:
		N = N_8192
		G = G_8192
		abLen = ab_8192_len
	default:
		return nil, errors.New("invalid security level - supported values: 2048, 3072, 4096, 6144, 8192")
	}

	// Calculate k parameter: k = H(N | G)
	K, err := calculateK(N, G, hashFunc)
	if err != nil {
		return nil, err
	}

	// Return configured SRP parameters
	return &Params{
		n:        N,
		g:        G,
		k:        K,
		abLen:    abLen,
		hashFunc: hashFunc,
		lenSalt:  lenSalt,
	}, nil
}

// padToLength pads a byte slice to the specified length with leading zeros
// If the input is already longer than the target length, it returns the original slice
// bytes - input byte slice to pad
// targetLen - desired length of the output slice
// Returns padded byte slice
func padToLength(bytes []byte, targetLen int) []byte {
	currentLen := len(bytes)
	if currentLen >= targetLen {
		return bytes
	}

	// Create padding of zeros
	padding := make([]byte, targetLen-currentLen)

	// Append original bytes after padding
	return append(padding, bytes...)
}

// calculateK computes the SRP multiplier parameter k
// k = H(N | G) where N and G are padded to the same length
// Follows RFC 5054 specification for parameter encoding
//
// Parameters:
//
//	n - large safe prime modulus
//	g - generator modulo n
//	hashFunc - cryptographic hash function to use
//
// Returns:
//
//	k - multiplier parameter as *big.Int
//	error - if validation fails or computation error occurs
func calculateK(n *big.Int, g *big.Int, hashFunc crypto.Hash) (*big.Int, error) {
	// Create new hash instance for computing k = H(N | G)
	h := hashFunc.New()

	// Get byte representations of N and G for hashing
	nBytes := n.Bytes()
	gBytes := g.Bytes()

	// Get lengths of N and G byte representations
	nLen := len(nBytes)
	gLen := len(gBytes)

	// If 'g' is shorter than 'n', the length is aligned using zero byte padding
	// This follows RFC 5054 specification for parameter encoding
	if nLen > gLen {
		// The highest byte of 'g' must not be zero according to RFC 5054
		// This ensures proper interpretation of the generator value
		if len(gBytes) > 0 && gBytes[0] == 0x00 {
			return nil, errors.New("highest byte of generator cannot be zero")
		}

		// Pad gBytes with leading zeros to match the length of nBytes
		// This ensures both values have the same byte length for hashing
		padding := make([]byte, nLen-gLen)
		gBytes = append(padding, gBytes...)
	}

	// Compute hash k = H(N | G)
	// Write N bytes followed by G bytes to the hash function
	h.Write(nBytes)
	h.Write(gBytes)

	// Get the hash result and convert to big integer
	kBytes := h.Sum(nil)
	k := new(big.Int).SetBytes(kBytes)

	// Debug output: print computed k value
	fmt.Printf("Debug calculateK - k: %x\n", k.Bytes())

	return k, nil
}

func (p *Params) generateM1Proof(SBytes []byte, ABytes []byte, BBytes []byte) []byte { // Calculate scrambling parameter U = H(PAD(A) | PAD(B))
	nLength := len(p.n.Bytes())
	uHash := p.hashFunc.New()
	uHash.Write(padToLength(ABytes, nLength))
	uHash.Write(padToLength(BBytes, nLength))
	uBytes := uHash.Sum(nil) // U = H(A | B)

	// Compute H(N) - hash of the prime modulus
	nHash := p.hashFunc.New()
	nHash.Write(p.n.Bytes())
	hN := nHash.Sum(nil)

	// Compute H(g) - hash of the generator
	gHash := p.hashFunc.New()
	gHash.Write(p.g.Bytes())
	hG := gHash.Sum(nil)

	// Compute H(N) XOR H(g)
	// Ensure both hashes have the same length by using the shorter one
	minLen := len(hN)
	if len(hG) < minLen {
		minLen = len(hG)
	}
	xorResult := make([]byte, minLen)
	for i := 0; i < minLen; i++ {
		xorResult[i] = hN[i] ^ hG[i]
	}

	// Compute the final proof M1 = H( H(N) XOR H(g) | H(U) | s | A | B | K )
	proof := p.hashFunc.New()
	proof.Write(xorResult)   // H(N) XOR H(g)
	proof.Write(uBytes)      // H(U) where U = H(A | B)
	proof.Write(SBytes)      // s - shared secret (session key)
	proof.Write(ABytes)      // A - client's public value
	proof.Write(BBytes)      // B - server's public value
	proof.Write(p.k.Bytes()) // K - SRP multiplier parameter

	return proof.Sum(nil)
}
