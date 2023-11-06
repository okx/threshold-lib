package zkp

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/pedersen"
)

type (
	AffGStatement struct {
		N, C, D *big.Int
		X, Y    *curves.ECPoint
	}

	AffGWitness struct {
		X, Y, Rho *big.Int
	}

	AffGProof struct {
		A, E, S, F, T, Z1, Z2, Z3, Z4, W *big.Int
		Bx, By, X, Y                     *curves.ECPoint
	}
)

var (
	two           = big.NewInt(2)
	curve         = secp256k1.S256()
	L0_Aff_G      = 2 * 256
	L1_Aff_G      = 3 * 256
	Epsilon_Aff_G = 3 * 256
)

// https://eprint.iacr.org/2020/492.pdf 4.2 Paillier Operation with Group Commitment in Range ZK
// y is committed in elliptic curve group instead of Paillier group
func PaillierAffineProve(pedersen *pedersen.PedersenParameters, st *AffGStatement, wit *AffGWitness) *AffGProof {
	N2 := new(big.Int).Mul(st.N, st.N)

	// sample viaribles
	rangeL0Epsilon := new(big.Int).Lsh(one, uint(L0_Aff_G+Epsilon_Aff_G))
	rangeL1Epsilon := new(big.Int).Lsh(one, uint(L1_Aff_G+Epsilon_Aff_G))
	rangeL0 := new(big.Int).Lsh(one, uint(L0_Aff_G))
	// rangeL1 := new(big.Int).Lsh(one, uint(L1_Aff_G))

	alpha := crypto.RandomNum(rangeL0Epsilon)
	beta := crypto.RandomNum(rangeL1Epsilon)

	r := crypto.RandomNum(st.N)
	gamma := crypto.RandomNum(new(big.Int).Mul(rangeL0Epsilon, pedersen.Ntilde))
	m := crypto.RandomNum(new(big.Int).Mul(rangeL0, pedersen.Ntilde))
	// rangeL1 ?
	delta := crypto.RandomNum(new(big.Int).Mul(rangeL0Epsilon, pedersen.Ntilde))
	mu := crypto.RandomNum(new(big.Int).Mul(rangeL0, pedersen.Ntilde))

	// compute A, Bx, By, E, S, F, T
	// A = C^alpha * ((1+N)^beta * r^N) mod N2
	A := new(big.Int).Exp(st.C, alpha, N2)
	A = new(big.Int).Mod(new(big.Int).Mul(A, new(big.Int).Exp(new(big.Int).Add(one, st.N), beta, N2)), N2)
	A = new(big.Int).Mod(new(big.Int).Mul(A, new(big.Int).Exp(r, st.N, N2)), N2)

	// Bx = aplha * G
	Bx := curves.ScalarToPoint(curve, alpha)

	// By = beta * G
	By := curves.ScalarToPoint(curve, beta)

	// E = pedersen.Commit(alpha, gamma)
	E, _ := pedersen.Commit(alpha, gamma)

	// S = pedersen.Commit(x, m)
	S, _ := pedersen.Commit(wit.X, m)

	// F = pedersen.Commit(beta, delta)
	F, _ := pedersen.Commit(beta, delta)

	// T = pedersen.Commit(y, mu)
	T, _ := pedersen.Commit(wit.Y, mu)

	// compute challenge e
	e := crypto.SHA256Int(st.N, st.C, st.D, st.X.X, st.Y.X, A, Bx.X, By.X, E, S, F, T)
	e = new(big.Int).Mod(e, curve.N)

	// compute Z1, Z2, Z3, Z4, W
	// Z1 = alpha + e * x
	Z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, wit.X))

	// Z2 = beta + e * y
	Z2 := new(big.Int).Add(beta, new(big.Int).Mul(e, wit.Y))

	// Z3 = gamma + e * m
	Z3 := new(big.Int).Add(gamma, new(big.Int).Mul(e, m))

	// Z4 = delta + e * mu
	Z4 := new(big.Int).Add(delta, new(big.Int).Mul(e, mu))

	// W = r * rho^e mod N
	W := new(big.Int).Mod(new(big.Int).Mul(r, new(big.Int).Exp(wit.Rho, e, st.N)), st.N)

	return &AffGProof{A: A, Bx: Bx, By: By, E: E, S: S, F: F, T: T, Z1: Z1, Z2: Z2, Z3: Z3, Z4: Z4, W: W, X: st.X, Y: st.Y}
}

func PaillierAffineVerify(pedersen *pedersen.PedersenParameters, proof *AffGProof, st *AffGStatement) bool {
	N2 := new(big.Int).Mul(st.N, st.N)
	e := crypto.SHA256Int(st.N, st.C, st.D, st.X.X, st.Y.X, proof.A, proof.Bx.X, proof.By.X, proof.E, proof.S, proof.F, proof.T)
	e = new(big.Int).Mod(e, curve.N)

	// check A
	// C^Z1 * ((1+N)^Z2 * w^N) = A * D^e mod N2
	left0 := new(big.Int).Exp(st.C, proof.Z1, N2)
	left0 = new(big.Int).Mod(new(big.Int).Mul(left0, new(big.Int).Exp(new(big.Int).Add(one, st.N), proof.Z2, N2)), N2)
	left0 = new(big.Int).Mod(new(big.Int).Mul(left0, new(big.Int).Exp(proof.W, st.N, N2)), N2)
	right0 := new(big.Int).Mod(new(big.Int).Mul(proof.A, new(big.Int).Exp(st.D, e, N2)), N2)
	if left0.Cmp(right0) != 0 {
		return false
	}

	// check Bx
	// Z1 * G = Bx + e * X
	left1 := curves.ScalarToPoint(curve, proof.Z1)
	right1, err := proof.Bx.Add(st.X.ScalarMult(e))
	if err != nil {
		return false
	}
	if !left1.Equals(right1) {
		return false
	}

	// check By
	// Z2 * G = By + e * Y
	left2 := curves.ScalarToPoint(curve, proof.Z2)
	right2, err := proof.By.Add(st.Y.ScalarMult(e))
	if err != nil {
		return false
	}
	if !left2.Equals(right2) {
		return false
	}

	// check E, S
	// pedersen.Commit(Z1, Z3) = E * S^e mod N2
	left3, _ := pedersen.Commit(proof.Z1, proof.Z3)
	right3 := new(big.Int).Mod(new(big.Int).Mul(proof.E, new(big.Int).Exp(proof.S, e, pedersen.Ntilde)), pedersen.Ntilde)
	if left3.Cmp(right3) != 0 {
		return false
	}

	// check F, T
	// pedersen.Commit(Z2, Z4) = F * T^e mod N2
	left4, _ := pedersen.Commit(proof.Z2, proof.Z4)
	right4 := new(big.Int).Mod(new(big.Int).Mul(proof.F, new(big.Int).Exp(proof.T, e, pedersen.Ntilde)), pedersen.Ntilde)
	if left4.Cmp(right4) != 0 {
		return false
	}

	// range check
	// Z1 < 2^(L0 + Epsilon)
	if proof.Z1.Cmp(new(big.Int).Lsh(one, uint(L0_Aff_G+Epsilon_Aff_G))) != -1 {
		return false
	}

	// Z2 < 2^(L1 + Epsilon)
	if proof.Z2.Cmp(new(big.Int).Lsh(one, uint(L1_Aff_G+Epsilon_Aff_G))) != -1 {
		return false
	}

	return true
}
