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
	"github.com/okx/threshold-lib/crypto/pedersen"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/zkp"
)

type P2Context struct {
	sessionID *big.Int

	x2        *big.Int // x = x1 + x2
	E_x1      *big.Int
	paiPub    *paillier.PublicKey
	PublicKey *ecdsa.PublicKey
	message   string
	k2        *big.Int
	cmtC      *commitment.Commitment
	p1_ped    *pedersen.PedersenParameters
}

// NewP1 2-party signature, P2 init
func NewP2(bobPri, E_x1 *big.Int, publicKey *ecdsa.PublicKey, paiPub *paillier.PublicKey, message string, p1_ped *pedersen.PedersenParameters) *P2Context {
	msg, err := hex.DecodeString(message)
	if err != nil {
		return nil
	}
	data := new(big.Int).SetBytes(msg)
	sessionId := crypto.SHA256Int(publicKey.X, publicKey.Y, data)

	p2Context := &P2Context{
		x2:        bobPri,
		E_x1:      E_x1,
		paiPub:    paiPub,
		PublicKey: publicKey,
		message:   message,
		sessionID: sessionId,
		p1_ped:    p1_ped,
	}
	return p2Context
}

func (p2 *P2Context) Step1(cmtC *commitment.Commitment) (*schnorr.Proof, *curves.ECPoint, error) {
	p2.cmtC = cmtC

	// random generate k2, k=k1*k2
	p2.k2 = crypto.RandomNum(curve.N)
	R2 := curves.ScalarToPoint(curve, p2.k2)
	proof, err := schnorr.ProveWithId(p2.sessionID, p2.k2, R2)
	if err != nil {
		return nil, nil, err
	}
	return proof, R2, nil
}

// Step2 paillier encrypt compute, return E[(h+xr)/k2]
func (p2 *P2Context) Step2(cmtD *commitment.Witness, p1Proof *schnorr.Proof) (*big.Int, *zkp.AffGProof, error) {
	q := curve.N
	// check R1=k1*G commitment
	commit := commitment.HashCommitment{}
	commit.C = *p2.cmtC
	commit.Msg = *cmtD
	ok, commitD := commit.Open()
	if !ok {
		return nil, nil, fmt.Errorf("commitment DeCommit fail")
	}
	if commitD[0].Cmp(p2.sessionID) != 0 {
		return nil, nil, fmt.Errorf("p2 Step2 commitment sessionId error")
	}
	R1, err := curves.NewECPoint(curve, commitD[1], commitD[2])
	if err != nil {
		return nil, nil, err
	}
	verify := schnorr.VerifyWithId(p2.sessionID, p1Proof, R1)
	if !verify {
		return nil, nil, fmt.Errorf("schnorr verify fail")
	}
	// R = k1*k2*G, k = k1*k2
	Rx, _ := curve.ScalarMult(R1.X, R1.Y, p2.k2.Bytes())
	r := new(big.Int).Mod(Rx, q)
	bytes, err := hex.DecodeString(p2.message)
	if err != nil {
		return nil, nil, err
	}
	k2_1 := new(big.Int).ModInverse(p2.k2, q)

	h := CalculateM(bytes)
	h = new(big.Int).Mul(h, k2_1) // h/k2

	rho := crypto.RandomNum(new(big.Int).Mul(q, q))
	rhoq := new(big.Int).Mul(rho, q)
	h_rhoq := new(big.Int).Add(h, rhoq) // h/k2 + rho*q

	paiPubKey := p2.paiPub
	N2 := new(big.Int).Mul(paiPubKey.N, paiPubKey.N)

	// s' = (h+r*(x1+x2))/k2 = a * x1 + b
	// a = r/k2, b = h/k2 + rho * q + r/k2 * x2
	a := new(big.Int).Mul(r, k2_1)                            // r/k2
	b := new(big.Int).Add(h_rhoq, new(big.Int).Mul(a, p2.x2)) // h/k2 + rho*q + r/k2 * x2
	rnd := crypto.RandomNum(paiPubKey.N)

	a_x1, _ := paiPubKey.HomoMulPlain(p2.E_x1, a)
	a_x1_b, _ := paiPubKey.HomoAddPlain(a_x1, b)
	E_k2_h_xr := new(big.Int).Mod(new(big.Int).Mul(a_x1_b, new(big.Int).Exp(rnd, paiPubKey.N, N2)), N2)
	A := curves.ScalarToPoint(curve, a)
	B := curves.ScalarToPoint(curve, b)

	st := &zkp.AffGStatement{
		N: paiPubKey.N,
		C: p2.E_x1,
		D: E_k2_h_xr,
		X: A,
		Y: B,
	}

	wit := &zkp.AffGWitness{
		X:   a,
		Y:   b,
		Rho: rnd,
	}
	aff_g_proof := zkp.PaillierAffineProve(p2.p1_ped, st, wit)

	return E_k2_h_xr, aff_g_proof, nil
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
