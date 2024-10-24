package zkp

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	four = big.NewInt(4)
)

// soundness error probability: 1/2^Q_bitlen
// completeness error probability: 2^Q_bitlen/2*Epsilon
type SecurityParameter struct {
	Q_bitlen uint
	Epsilon  uint
}

var curve = secp256k1.S256()
