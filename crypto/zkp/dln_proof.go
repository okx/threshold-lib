package zkp

import (
	"math/big"

	"github.com/okx/threshold-lib/crypto"
)

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product

// A proof of knowledge of the discrete log of an element h2 = hx1 with respect to h1.
// In our protocol, we will run two of these in parallel to prove that two elements h1,h2 generate the same group modN.

const Iterations = 30

type (
	DlnProof struct {
		Alpha,
		T [Iterations]*big.Int
	}
)

func NewDlnProve(h1, h2, x, p, q, N *big.Int) *DlnProof {
	pq := new(big.Int).Mul(p, q)

	a := make([]*big.Int, Iterations)
	alpha := [Iterations]*big.Int{}
	for i := range alpha {
		a[i] = crypto.RandomNum(pq)
		alpha[i] = new(big.Int).Exp(h1, a[i], N)
	}
	msg := append([]*big.Int{h1, h2, N}, alpha[:]...)
	c := crypto.SHA256Int(msg...)
	t := [Iterations]*big.Int{}
	cIBI := new(big.Int)
	for i := range t {
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		t[i] = new(big.Int).Add(a[i], new(big.Int).Mul(cIBI, x))
		t[i] = new(big.Int).Mod(t[i], pq)
	}
	return &DlnProof{alpha, t}
}

func DlnVerify(dp *DlnProof, h1, h2, N *big.Int) bool {
	if dp == nil || h1 == nil || h2 == nil || N == nil || N.Sign() != 1 {
		return false
	}

	h1_ := new(big.Int).Mod(h1, N)
	if h1_.Cmp(one) != 1 || h1_.Cmp(N) != -1 {
		return false
	}
	h2_ := new(big.Int).Mod(h2, N)
	if h2_.Cmp(one) != 1 || h2_.Cmp(N) != -1 {
		return false
	}
	if h1_.Cmp(h2_) == 0 {
		return false
	}
	for i := range dp.T {
		a := new(big.Int).Mod(dp.T[i], N)
		if a.Cmp(one) != 1 || a.Cmp(N) != -1 {
			return false
		}
	}
	for i := range dp.Alpha {
		a := new(big.Int).Mod(dp.Alpha[i], N)
		if a.Cmp(one) != 1 || a.Cmp(N) != -1 {
			return false
		}
	}

	msg := append([]*big.Int{h1, h2, N}, dp.Alpha[:]...)
	c := crypto.SHA256Int(msg...)
	cIBI := new(big.Int)
	for i := 0; i < Iterations; i++ {
		if dp.Alpha[i] == nil || dp.T[i] == nil {
			return false
		}
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		h1ExpTi := new(big.Int).Exp(h1, dp.T[i], N)
		h2ExpCi := new(big.Int).Exp(h2, cIBI, N)
		alphaIMulH2ExpCi := new(big.Int).Mul(dp.Alpha[i], h2ExpCi)
		alphaIMulH2ExpCi = new(big.Int).Mod(alphaIMulH2ExpCi, N)
		if h1ExpTi.Cmp(alphaIMulH2ExpCi) != 0 {
			return false
		}
	}
	return true
}
