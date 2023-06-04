package zkp

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"math/big"
)

// partly ported from:
// https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/src/utilities/zk_pdl_with_slack/mod.rs

// We use the proof as given in proof PIi in https://eprint.iacr.org/2016/013.pdf.
// This proof ws taken from the proof 6.3 (left side ) in https://www.cs.unc.edu/~reiter/papers/2004/IJIS.pdf
//
// Statement: (c, pk, Q, G)
// witness (x, r) such that Q = xG, c = Enc(pk, x, r)
// note that because of the range proof, the proof has a slack in the range: x in [-q^3, q^3]

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

// NewPDLwSlackProof
func NewPDLwSlackProve(wit *PDLwSlackWitness, st *PDLwSlackStatement) (*PDLwSlackProof, *StatementParams) {
	q2 := new(big.Int).Mul(q, q)
	q3 := new(big.Int).Mul(q2, q)
	qNTilde := new(big.Int).Mul(q, st.NTilde)
	q3NTilde := new(big.Int).Mul(q3, st.NTilde)

	alpha := crypto.RandomNum(q3)
	beta, err := crypto.RandomPrimeNum(st.N)
	if err != nil {
		return nil, nil
	}
	rho := crypto.RandomNum(qNTilde)
	gamma := crypto.RandomNum(q3NTilde)

	// z = h1^x * h2^rho mod NTilde
	z := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, wit.X, rho)
	// u1 = alpha*G
	u1 := st.G.ScalarMult(alpha)
	nOne := new(big.Int).Add(st.N, one)
	nSquare := new(big.Int).Mul(st.N, st.N)
	// u2 = nOne^alpha * beta^N mod N2
	u2 := commitmentUnknownOrder(nOne, beta, nSquare, alpha, st.N)
	// u3 = h1^ alpha * h2^gamma mod NTilde
	u3 := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, alpha, gamma)

	e := crypto.SHA256Int(st.G.X, st.G.Y, st.Q.X, st.Q.Y, st.CipherText, z, u1.X, u1.Y, u2, u3)

	// s1 = e*x + alpha
	s1 := new(big.Int).Add(new(big.Int).Mul(e, wit.X), alpha)
	// s2 = r^e * beta mod N
	s2 := commitmentUnknownOrder(wit.R, beta, st.N, e, one)
	// s3 = e*rho + gamma
	s3 := new(big.Int).Add(new(big.Int).Mul(e, rho), gamma)

	proof := &PDLwSlackProof{z, u1, u2, u3, s1, s2, s3}
	statement := &StatementParams{st.H1, st.H2, st.NTilde}
	return proof, statement
}

// PDLwSlackVerify
func PDLwSlackVerify(pf *PDLwSlackProof, st *PDLwSlackStatement) bool {
	if pf == nil || st == nil {
		return false
	}
	e := crypto.SHA256Int(st.G.X, st.G.Y, st.Q.X, st.Q.Y, st.CipherText, pf.Z, pf.U1.X, pf.U1.Y, pf.U2, pf.U3)

	// u1 = s1*G + (q-e)*Q
	gS1 := st.G.ScalarMult(pf.S1)
	eFeNeg := new(big.Int).Sub(q, e)
	yMinusE := st.Q.ScalarMult(eFeNeg)
	u1, err := gS1.Add(yMinusE)
	if err != nil {
		return false
	}

	nOne, eNeg := new(big.Int).Add(st.N, one), new(big.Int).Neg(e)
	nSquare := new(big.Int).Mul(st.N, st.N)
	// u2 = nOne^s1 * s2^N * w^(-e) mod N2
	u2Tmp := commitmentUnknownOrder(nOne, pf.S2, nSquare, pf.S1, st.N)
	u2 := commitmentUnknownOrder(u2Tmp, st.CipherText, nSquare, one, eNeg)

	// u3 = h1^s1 * h2^s3 * z^(-e) mod NTilde
	u3Tmp := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, pf.S1, pf.S3)
	u3 := commitmentUnknownOrder(u3Tmp, pf.Z, st.NTilde, one, eNeg)

	return pf.U1.Equals(u1) && pf.U2.Cmp(u2) == 0 && pf.U3.Cmp(u3) == 0
}

// c = h1^x * h2^r mod NTilde
func commitmentUnknownOrder(h1, h2, NTilde, x, r *big.Int) (com *big.Int) {
	h1X := new(big.Int).Exp(h1, x, NTilde)
	h2R := new(big.Int).Exp(h2, r, NTilde)
	com = new(big.Int).Mul(h1X, h2R)
	com = new(big.Int).Mod(com, NTilde)
	return
}
