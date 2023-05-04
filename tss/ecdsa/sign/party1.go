package sign

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/crypto/schnorr"
)

var (
	curve = secp256k1.S256()
)

type P1Context struct {
	publicKey *ecdsa.PublicKey
	paiPriKey *paillier.PrivateKey

	k1      *big.Int
	message string
	R2      *curves.ECPoint // k2*G
	cmtD    *commitment.Witness
}

// NewP1 2-party signature, P1 init
func NewP1(publicKey *ecdsa.PublicKey, message string, paiPriKey *paillier.PrivateKey) *P1Context {
	// random generate k1, k=k1*k2
	k1 := crypto.RandomNum(curve.N)
	p1Context := &P1Context{
		k1:        k1,
		publicKey: publicKey,
		message:   message,
		paiPriKey: paiPriKey,
	}
	return p1Context
}

func (p1 *P1Context) Step1() (*commitment.Commitment, error) {
	R1 := curves.ScalarToPoint(curve, p1.k1)
	cmt := commitment.NewCommitment(R1.X, R1.Y)
	p1.cmtD = &cmt.Msg
	return &cmt.C, nil
}

func (p1 *P1Context) Step2(p2Proof *schnorr.Proof, R2 *curves.ECPoint) (*schnorr.Proof, *commitment.Witness, error) {
	// zk schnorr verify k2
	verify := schnorr.Verify(p2Proof, R2)
	if !verify {
		return nil, nil, fmt.Errorf("schnorr verify fail")
	}
	p1.R2 = R2
	// zk schnorr prove k1
	R1 := curves.ScalarToPoint(curve, p1.k1)
	proof, err := schnorr.Prove(p1.k1, R1)
	if err != nil {
		return nil, nil, err
	}
	return proof, p1.cmtD, nil
}

func (p1 *P1Context) Step3(E_k2_h_xr *big.Int) (*big.Int, *big.Int, error) {
	q := curve.N
	// R = k1*k2*G, k = k1*k2
	Rx, _ := curve.ScalarMult(p1.R2.X, p1.R2.Y, p1.k1.Bytes())
	r := new(big.Int).Mod(Rx, q)
	// paillier Decrypt (h+xr)/k2
	k2_h_xr, err := p1.paiPriKey.Decrypt(E_k2_h_xr)
	if err != nil {
		return nil, nil, err
	}
	k1_1 := new(big.Int).ModInverse(p1.k1, q)
	// s = (h+r*(x1+x2))/(k1*k2)
	s := new(big.Int).Mod(new(big.Int).Mul(k2_h_xr, k1_1), q)

	halfOrder := new(big.Int).Rsh(q, 1)
	if s.Cmp(halfOrder) == 1 {
		s.Sub(q, s)
	}
	if s.Sign() == 0 {
		return nil, nil, fmt.Errorf("calculated S is zero")
	}
	message, err := hex.DecodeString(p1.message)
	if err != nil {
		return nil, nil, err
	}
	// check ecdsa signature
	ok := ecdsa.Verify(p1.publicKey, message, r, s)
	if !ok {
		return nil, nil, fmt.Errorf("ecdsa sign verify fail")
	}
	return r, s, nil
}
