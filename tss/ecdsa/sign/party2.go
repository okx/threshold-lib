package sign

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/crypto/schnorr"
)

type P2Context struct {
	x2        *big.Int // x = x1 + x2
	E_x1      *big.Int
	paiPub    *paillier.PublicKey
	PublicKey *ecdsa.PublicKey
	message   string
	k2        *big.Int
	cmtC      *commitment.Commitment
}

// NewP1 2-party signature, P2 init
func NewP2(bobPri, E_x1 *big.Int, publicKey *ecdsa.PublicKey, paiPub *paillier.PublicKey, message string) *P2Context {
	p2Context := &P2Context{
		x2:        bobPri,
		E_x1:      E_x1,
		paiPub:    paiPub,
		PublicKey: publicKey,
		message:   message,
	}
	return p2Context
}

func (p2 *P2Context) Step1(cmtC *commitment.Commitment) (*schnorr.Proof, *curves.ECPoint, error) {
	_, err := hex.DecodeString(p2.message)
	if err != nil {
		return nil, nil, err
	}
	p2.cmtC = cmtC

	// random generate k2, k=k1*k2
	p2.k2 = crypto.RandomNum(curve.N)
	R2 := curves.ScalarToPoint(curve, p2.k2)
	proof, err := schnorr.Prove(p2.k2, R2)
	if err != nil {
		return nil, nil, err
	}
	return proof, R2, nil
}

// Step2 paillier encrypt compute, return E[(h+xr)/k2]
func (p2 *P2Context) Step2(cmtD *commitment.Witness, p1Proof *schnorr.Proof) (*big.Int, error) {
	q := curve.N
	// check R1=k1*G commitment
	commit := commitment.HashCommitment{}
	commit.C = *p2.cmtC
	commit.Msg = *cmtD
	ok, commitD := commit.Open()
	if !ok {
		return nil, fmt.Errorf("commitment DeCommit fail")
	}
	R1, err := curves.NewECPoint(curve, commitD[0], commitD[1])
	if err != nil {
		return nil, err
	}
	verify := schnorr.Verify(p1Proof, R1)
	if !verify {
		return nil, fmt.Errorf("schnorr verify fail")
	}
	// R = k1*k2*G, k = k1*k2
	Rx, _ := curve.ScalarMult(R1.X, R1.Y, p2.k2.Bytes())
	r := new(big.Int).Mod(Rx, q)
	bytes, err := hex.DecodeString(p2.message)
	if err != nil {
		return nil, err
	}
	k2_1 := new(big.Int).ModInverse(p2.k2, q)

	h := CalculateM(bytes)
	h = new(big.Int).Mul(h, k2_1) // h/k2

	rho := crypto.RandomNum(new(big.Int).Mul(q, q))
	rhoq := new(big.Int).Mul(rho, q)
	h_rhoq := new(big.Int).Add(h, rhoq) // h/k2 + rho*q

	E_x, err := p2.paiPub.HomoAddPlain(p2.E_x1, p2.x2)
	if err != nil {
		return nil, err
	}
	r = new(big.Int).Mul(r, k2_1) //  r/k2
	E_xr, err := p2.paiPub.HomoMulPlain(E_x, r)
	if err != nil {
		return nil, err
	}
	E_k2_h_xr, err := p2.paiPub.HomoAddPlain(E_xr, h_rhoq)
	if err != nil {
		return nil, err
	}
	return E_k2_h_xr, nil
}

func CalculateM(hash []byte) *big.Int {
	orderBits := curve.N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}
	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
