// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product

// A proof of knowledge of the discrete log of an element h2 = hx1 with respect to h1.
// In our protocol, we will run two of these in parallel to prove that two elements h1,h2 generate the same group modN.

package zkp

import (
	"github.com/okx/threshold-lib/crypto"
	"math/big"
)

const Iterations = 12

type (
	DlnProof struct {
		Alpha,
		T [Iterations]*big.Int
	}
)

func NewDlnProof(h1, h2, x, p, q, N *big.Int) *DlnProof {
	pMulQ := new(big.Int).Mul(p, q)

	a := make([]*big.Int, Iterations)
	alpha := [Iterations]*big.Int{}
	for i := range alpha {
		a[i] = crypto.RandomNum(pMulQ)
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
		t[i] = new(big.Int).Mod(t[i], pMulQ)
	}
	return &DlnProof{alpha, t}
}

func (p *DlnProof) Verify(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}
	msg := append([]*big.Int{h1, h2, N}, p.Alpha[:]...)
	c := crypto.SHA256Int(msg...)
	cIBI := new(big.Int)
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		h1ExpTi := new(big.Int).Exp(h1, p.T[i], N)
		h2ExpCi := new(big.Int).Exp(h2, cIBI, N)
		alphaIMulH2ExpCi := new(big.Int).Mul(p.Alpha[i], h2ExpCi)
		alphaIMulH2ExpCi = new(big.Int).Mod(alphaIMulH2ExpCi, N)
		if h1ExpTi.Cmp(alphaIMulH2ExpCi) != 0 {
			return false
		}
	}
	return true
}
