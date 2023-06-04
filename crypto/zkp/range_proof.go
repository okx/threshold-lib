package zkp

import (
	"fmt"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/paillier"
	"math/big"
)

type (
	RangeProof struct {
		Z, U, W, S, S1, S2 *big.Int
	}
)

// https://eprint.iacr.org/2019/114.pdf A.1 Range Proof
// RangeProve
func RangeProve(pk *paillier.PublicKey, NTilde, h1, h2, c, r, m *big.Int) (*RangeProof, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c == nil || r == nil || m == nil {
		return nil, fmt.Errorf("RangeProve parameters error")
	}

	q2 := new(big.Int).Mul(q, q)
	q3 := new(big.Int).Mul(q2, q)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	alpha := crypto.RandomNum(q3)
	beta, err := crypto.RandomPrimeNum(pk.N)
	if err != nil {
		return nil, err
	}
	gamma := crypto.RandomNum(q3NTilde)
	rho := crypto.RandomNum(qNTilde)

	// z = h1^m * h2^ρ mod NTilde
	h1M := new(big.Int).Exp(h1, m, NTilde)
	h2Rho := new(big.Int).Exp(h2, rho, NTilde)
	z := new(big.Int).Mod(new(big.Int).Mul(h1M, h2Rho), NTilde)

	// u = gamma^alpha * beta^N mod N2
	n2 := pk.N2()
	gAlpha := new(big.Int).Exp(pk.G(), alpha, n2)
	betaN := new(big.Int).Exp(beta, pk.N, n2)
	u := new(big.Int).Mod(new(big.Int).Mul(gAlpha, betaN), n2)

	// w = h1^alpha * h2^gamma mod NTilde
	h1Alpha := new(big.Int).Exp(h1, alpha, NTilde)
	h2Gamma := new(big.Int).Exp(h2, gamma, NTilde)
	w := new(big.Int).Mod(new(big.Int).Mul(h1Alpha, h2Gamma), NTilde)

	// e
	eHash := crypto.SHA256Int(pk.N, c, z, u, w)
	e := new(big.Int).Mod(eHash, q)

	// s = r^e*beta
	rE := new(big.Int).Exp(r, e, pk.N)
	s := new(big.Int).Mod(new(big.Int).Mul(rE, beta), pk.N)

	// s1 = e * m + alpha
	eM := new(big.Int).Mul(e, m)
	s1 := new(big.Int).Add(eM, alpha)

	// s2 = e * rho + gamma
	eRho := new(big.Int).Mul(e, rho)
	s2 := new(big.Int).Add(eRho, gamma)

	return &RangeProof{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}, nil
}

// RangeVerify
func RangeVerify(rp *RangeProof, pk *paillier.PublicKey, NTilde, h1, h2, c *big.Int) bool {
	if rp == nil || pk == nil || NTilde == nil || h1 == nil || h2 == nil || c == nil {
		return false
	}

	q2 := new(big.Int).Mul(q, q)
	q3 := new(big.Int).Mul(q2, q)
	NSq := new(big.Int).Mul(pk.N, pk.N)

	// 1. s1 ≤ q^3
	if rp.S1.Cmp(q3) == 1 {
		return false
	}

	// e
	eHash := crypto.SHA256Int(pk.N, c, rp.Z, rp.U, rp.W)
	e := new(big.Int).Mod(eHash, q)

	minusE := new(big.Int).Sub(big.NewInt(0), e)
	{ // 2. u = gamma^s1 * s^N * c^-e
		cMinusE := new(big.Int).Exp(c, minusE, NSq)
		sN := new(big.Int).Exp(rp.S, pk.N, NSq)
		gammaS1 := new(big.Int).Exp(pk.G(), rp.S1, NSq)

		tmp := new(big.Int).Mul(cMinusE, sN)
		tmp = new(big.Int).Mul(tmp, gammaS1)
		tmp = new(big.Int).Mod(tmp, NSq)
		if rp.U.Cmp(tmp) != 0 {
			return false
		}
	}

	{ // 3. w = h1^s1 * h2^s2 * z^-e
		h1S1 := new(big.Int).Exp(h1, rp.S1, NTilde)
		h2S2 := new(big.Int).Exp(h2, rp.S2, NTilde)
		zMinusE := new(big.Int).Exp(rp.Z, minusE, NTilde)

		tmp := new(big.Int).Mul(h1S1, h2S2)
		tmp = new(big.Int).Mul(tmp, zMinusE)
		tmp = new(big.Int).Mod(tmp, NTilde)
		if rp.W.Cmp(tmp) != 0 {
			return false
		}
	}
	return true
}
