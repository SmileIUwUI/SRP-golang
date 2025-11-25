package srp

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// GenerateVerifier generates a salt and verifier for SRP registration
// The process follows: x = H(salt | H(username | ":" | password))
// verifier = g^x mod N
// Returns verifier, salt as byte slices, and any error encountered
func (p *Params) GenerateVerifier(username string, password string) ([]byte, []byte, error) {
	// Generate x and salt using the generatorX function
	xBytes, salt, err := generatorX(username, password, p.lenSalt, p.hashFunc, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate verifier: %w", err)
	}

	// Convert hash output to a big integer
	x := new(big.Int).SetBytes(xBytes)

	// Compute verifier: v = g^x mod N
	v := new(big.Int).Exp(p.g, x, p.n)

	return v.Bytes(), salt, nil
}

// GenerateKeyEphemeralClient generates client's ephemeral key pair for SRP authentication
// Returns:
//   - clientPublic (A) - client's public key A = g^a mod N
//   - clientPrivate (a) - client's private ephemeral value
//   - error if any operation fails
func (p *Params) GenerateKeyEphemeralClient() (public []byte, private []byte, err error) {
	// Generate client's private ephemeral value a with sufficient entropy
	byteLen := (p.abLen + 7) / 8 // Convert bits to bytes (rounding up)
	aBytes := make([]byte, byteLen)
	_, errRead := rand.Read(aBytes)
	if errRead != nil {
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

// GenerateSharedKeyClient computes the client's shared session key
// using the formula: S = (B - (k * g^x)) ^ (a + (u * x)) % N
// username - client username
// password - client password
// salt - salt used during registration
// ABytes - client's public ephemeral value A
// BBytes - server's public ephemeral value B
// aBytes - client's private ephemeral value a
// Returns the shared secret S or error if computation fails
func (p *Params) GenerateSharedKeyClient(username string, password string, salt []byte, ABytes []byte, BBytes []byte, aBytes []byte) ([]byte, error) {
	// Validate input parameters
	if len(username) == 0 || len(password) == 0 || len(salt) == 0 ||
		len(ABytes) == 0 || len(BBytes) == 0 || len(aBytes) == 0 {
		return nil, errors.New("all input parameters must be non-empty")
	}

	// Calculate x = H(salt | H(username | ":" | password))
	xBytes, _, err := generatorX(username, password, 0, p.hashFunc, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate x: %w", err)
	}

	// Calculate scrambling parameter u = H(PAD(A) | PAD(B))
	nLength := len(p.n.Bytes())
	uHash := p.hashFunc.New()
	uHash.Write(padToLength(ABytes, nLength))
	uHash.Write(padToLength(BBytes, nLength))
	u := new(big.Int).SetBytes(uHash.Sum(nil))

	// Convert byte slices to big.Int
	B := new(big.Int).SetBytes(BBytes)
	x := new(big.Int).SetBytes(xBytes)
	a := new(big.Int).SetBytes(aBytes)

	// RFC 5054 security validation: B must not be 0 and must be less than N
	if B.Sign() == 0 {
		return nil, errors.New("server public value B cannot be zero")
	}
	if B.Cmp(p.n) >= 0 {
		return nil, errors.New("server public value B must be less than N")
	}

	// Compute shared secret using client formula: S = (B - (k * g^x)) ^ (a + (u * x)) % N

	// Step 1: Compute k * g^x mod N
	gx := new(big.Int).Exp(p.g, x, p.n) // g^x mod N
	kgx := new(big.Int).Mul(p.k, gx)    // k * g^x
	kgx.Mod(kgx, p.n)                   // (k * g^x) mod N

	// Step 2: Compute B - (k * g^x) mod N
	// Handle negative result by adding N if needed
	base := new(big.Int).Sub(B, kgx)
	if base.Sign() < 0 {
		base.Add(base, p.n)
	}
	base.Mod(base, p.n)

	// Ensure base is not zero
	if base.Sign() == 0 {
		return nil, errors.New("base for exponentiation cannot be zero")
	}

	// Step 3: Compute exponent (a + u * x)
	exponent := new(big.Int).Mul(u, x) // u * x
	exponent.Add(exponent, a)          // a + u * x
	exponent.Mod(exponent, p.n)        // (a + u * x) mod N

	// Step 4: Compute S = base^exponent mod N
	S := new(big.Int).Exp(base, exponent, p.n)

	// Ensure shared secret is not zero
	if S.Sign() == 0 {
		return nil, errors.New("computed shared secret cannot be zero")
	}

	return S.Bytes(), nil
}

// generatorX computes x = H(salt | H(username | ":" | password))
// If salt is provided, it uses that salt; otherwise generates a new one
// Returns x value and salt used
func generatorX(username string, password string, lenSalt int16, hashFunc crypto.Hash, salt []byte) ([]byte, []byte, error) {
	// Compute H(username | ":" | password)
	dataHash := hashFunc.New()
	dataHash.Write([]byte(username + ":" + password))
	userPassHash := dataHash.Sum(nil)

	var saltGenerate []byte
	if salt == nil {
		saltGenerate = make([]byte, lenSalt)
		_, err := rand.Read(saltGenerate)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	} else {
		saltGenerate = salt
	}

	// Compute x = H(salt | H(username | ":" | password))
	xHash := hashFunc.New()
	xHash.Write(saltGenerate)
	xHash.Write(userPassHash)
	xBytes := xHash.Sum(nil)

	return xBytes, saltGenerate, nil
}

// GenerateClientProof generates the client's key confirmation proof (M1)
// according to RFC 2945 formula: M1 = H( H(N) XOR H(g) | H(U) | s | A | B | K )
// This proves that the client possesses the correct session key
//
// Parameters:
//
//	SBytes - shared secret S (session key)
//	ABytes - client's public ephemeral value A
//	BBytes - server's public ephemeral value B
//
// Returns:
//
//	[]byte - client proof M1
func (p *Params) GenerateClientProof(SBytes []byte, ABytes []byte, BBytes []byte) []byte {
	return p.generateM1Proof(SBytes, ABytes, BBytes)
}
