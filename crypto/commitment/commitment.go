package commitment

import (
	"crypto/rand"
	"math/big"

	"github.com/okx/threshold-lib/crypto"
)

type (
	Commitment = *big.Int
	Witness    = []*big.Int

	HashCommitment struct {
		C   Commitment
		Msg Witness
	}
)

// NewCommitment commit []*big.int use sha512
func NewCommitment(secrets ...*big.Int) *HashCommitment {
	var rBytes [32]byte
	_, err := rand.Read(rBytes[:])
	if err != nil {
		return nil
	}
	r := new(big.Int).SetBytes(rBytes[:])
	parts := make([]*big.Int, len(secrets)+1)
	parts[0] = r
	for i := 1; i < len(parts); i++ {
		parts[i] = secrets[i-1]
	}
	hash := crypto.SHA512Int(parts...)

	cmt := &HashCommitment{}
	cmt.C = hash
	cmt.Msg = parts
	return cmt
}

// Verify verify the commitment
func (cmt *HashCommitment) Verify() bool {
	C, D := cmt.C, cmt.Msg
	if C == nil || D == nil {
		return false
	}
	hash := crypto.SHA512Int(D...)
	return hash.Cmp(C) == 0
}

// Open open the commitment
func (cmt *HashCommitment) Open() (bool, Witness) {
	if cmt.Verify() {
		return true, cmt.Msg[1:]
	} else {
		return false, nil
	}
}
