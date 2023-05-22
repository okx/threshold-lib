// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// go port of https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/src/utilities/zk_pdl_with_slack/mod.rs

// We use the proof as given in proof PIi in https://eprint.iacr.org/2016/013.pdf.
// This proof ws taken from the proof 6.3 (left side ) in https://www.cs.unc.edu/~reiter/papers/2004/IJIS.pdf
//
// Statement: (c, pk, Q, G)
// witness (x, r) such that Q = xG, c = Enc(pk, x, r)
// note that because of the range proof, the proof has a slack in the range: x in [-q^3, q^3]
package zkp

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"math/big"
)

type (
	PDLwSlackStatement struct {
		CipherText     *big.Int
		N              *big.Int
		Q, G           *curves.ECPoint
		H1, H2, NTilde *big.Int
	}

	StatementParams struct {
		H1, H2, NTilde *big.Int
	}

	PDLwSlackWitness struct {
		X, R *big.Int
	}

	PDLwSlackProof struct {
		Z          *big.Int
		U1         *curves.ECPoint
		U2, U3     *big.Int
		S1, S2, S3 *big.Int
	}
)

var (
	one = big.NewInt(1)
	q   = secp256k1.S256().N
)

func NewPDLwSlackProof(wit *PDLwSlackWitness, st *PDLwSlackStatement) (*PDLwSlackProof, *StatementParams) {
	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	qNTilde := new(big.Int).Mul(q, st.NTilde)
	q3NTilde := new(big.Int).Mul(q3, st.NTilde)

	alpha := crypto.RandomNum(q3)
	nSubOne := new(big.Int).Add(st.N, one)
	beta := new(big.Int).Add(one, crypto.RandomNum(nSubOne))
	rho := crypto.RandomNum(qNTilde)
	gamma := crypto.RandomNum(q3NTilde)

	z := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, wit.X, rho)
	u1 := st.G.ScalarMult(alpha)
	nOne := new(big.Int).Add(st.N, one)
	nSquare := new(big.Int).Mul(st.N, st.N)
	u2 := commitmentUnknownOrder(nOne, beta, nSquare, alpha, st.N)
	u3 := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, alpha, gamma)

	e := crypto.SHA256Int(st.G.X, st.G.Y, st.Q.X, st.Q.Y, st.CipherText, z, u1.X, u1.Y, u2, u3)

	s1 := new(big.Int).Mul(e, wit.X)
	s3 := new(big.Int).Mul(e, rho)
	s1.Add(s1, alpha)
	s2 := commitmentUnknownOrder(wit.R, beta, st.N, e, one)
	s3.Add(s3, gamma)

	proof := &PDLwSlackProof{z, u1, u2, u3, s1, s2, s3}
	statement := &StatementParams{st.H1, st.H2, st.NTilde}
	return proof, statement
}

func PDLwSlackVerify(pf *PDLwSlackProof, st *PDLwSlackStatement) bool {
	e := crypto.SHA256Int(st.G.X, st.G.Y, st.Q.X, st.Q.Y, st.CipherText, pf.Z, pf.U1.X, pf.U1.Y, pf.U2, pf.U3)

	gS1 := st.G.ScalarMult(pf.S1)
	eFeNeg := new(big.Int).Sub(q, e)
	yMinusE := st.Q.ScalarMult(eFeNeg)
	u1Test, err := gS1.Add(yMinusE)
	if err != nil {
		return false
	}

	nOne, eNeg := new(big.Int).Add(st.N, one), new(big.Int).Neg(e)
	nSquare := new(big.Int).Mul(st.N, st.N)
	u2TestTmp := commitmentUnknownOrder(nOne, pf.S2, nSquare, pf.S1, st.N)
	u2Test := commitmentUnknownOrder(u2TestTmp, st.CipherText, nSquare, one, eNeg)
	u3TestTmp := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, pf.S1, pf.S3)
	u3Test := commitmentUnknownOrder(u3TestTmp, pf.Z, st.NTilde, one, eNeg)

	return pf.U1.Equals(u1Test) &&
		pf.U2.Cmp(u2Test) == 0 &&
		pf.U3.Cmp(u3Test) == 0
}

func commitmentUnknownOrder(h1, h2, NTilde, x, r *big.Int) (com *big.Int) {
	h1X := new(big.Int).Exp(h1, x, NTilde)
	h2R := new(big.Int).Exp(h2, r, NTilde)
	com = new(big.Int).Mul(h1X, h2R)
	com = new(big.Int).Mod(com, NTilde)
	return
}
