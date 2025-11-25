package srp

import (
	"crypto"
	"errors"
	"math/big"
)

type Params struct {
	n        *big.Int
	g        *big.Int
	k        *big.Int
	hashFunc crypto.Hash
	lenSalt  int16
}

func NewParams(secure int16, hashFunc crypto.Hash, lenSalt int16) (*Params, error) {
	if lenSalt < 8 {
		return nil, errors.New("salt length too short")
	}
	if !hashFunc.Available() {
		return nil, errors.New("hash function not available")
	}

	var N, G *big.Int

	switch secure {
	case 2048:
		N = N_2048
		G = G_2048
	case 3072:
		N = N_3072
		G = G_3072
	case 4096:
		N = N_4096
		G = G_4096
	case 6144:
		N = N_6144
		G = G_6144
	case 8192:
		N = N_8192
		G = G_8192
	default:
		return nil, errors.New("secure is invalid")
	}

	K, err := calculateK(N, G, hashFunc)

	if err != nil {
		return nil, err
	}

	return &Params{
		n:        N,
		g:        G,
		k:        K,
		hashFunc: hashFunc,
		lenSalt:  lenSalt,
	}, nil
}

func calculateK(n *big.Int, g *big.Int, hashFunc crypto.Hash) (*big.Int, error) {
	h := hashFunc.New()

	nBytes := n.Bytes()
	gBytes := g.Bytes()

	nLen := len(nBytes)
	gLen := len(gBytes)
	if nLen > gLen {
		if len(gBytes) > 0 && gBytes[0] == 0x00 {
			return big.NewInt(0), errors.New("the highest byte 'g' cannot be zero")
		}

		padding := make([]byte, nLen-gLen)
		gBytes = append(padding, gBytes...)
	}

	h.Write(nBytes)
	h.Write(gBytes)

	return new(big.Int).SetBytes(h.Sum(nil)), nil
}
