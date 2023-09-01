package zkp

import (
	"math/big"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/pedersen"
)

type (
	NoSmallFactorProof struct {
		P, Q, A, B, T, Rho, Z1, Z2, W1, W2, V *big.Int
	}
)

var (
	L_NSF       = 256
	Epsilon_NSF = 2 * 256
)

func NoSmallFactorProve(N, p, q *big.Int, ped *pedersen.PedersenParameters) *NoSmallFactorProof {
	Ntilde := ped.Ntilde
	Nsqrt := new(big.Int).Sqrt(N)

	range0 := new(big.Int).Lsh(one, uint(L_NSF+Epsilon_NSF))
	range1 := new(big.Int).Lsh(one, uint(L_NSF))

	alpha := crypto.RandomNum(new(big.Int).Mul(range0, Nsqrt))
	beta := crypto.RandomNum(new(big.Int).Mul(range0, Nsqrt))
	mu := crypto.RandomNum(new(big.Int).Mul(range0, Ntilde))
	nu := crypto.RandomNum(new(big.Int).Mul(range0, Ntilde))
	Rho := crypto.RandomNum(new(big.Int).Mul(range1, new(big.Int).Mul(N, Ntilde)))
	r := crypto.RandomNum(new(big.Int).Mul(range0, new(big.Int).Mul(N, Ntilde)))
	x := crypto.RandomNum(new(big.Int).Mul(range0, Ntilde))
	y := crypto.RandomNum(new(big.Int).Mul(range0, Ntilde))

	// calculate P, Q, A, B, T
	P, _ := ped.Commit(p, mu)
	Q, _ := ped.Commit(q, nu)
	A, _ := ped.Commit(alpha, x)
	B, _ := ped.Commit(beta, y)
	T := new(big.Int).Mul(new(big.Int).Exp(Q, alpha, Ntilde), new(big.Int).Exp(ped.T, r, Ntilde))

	// calculate challenge e
	e := crypto.SHA256Int(N, P, Q, A, B, T, Rho)
	e = new(big.Int).Mod(e, curve.N)

	RhoTilde := new(big.Int).Sub(Rho, new(big.Int).Mul(nu, p))

	// calculate Z1, Z2, W1, W2, V
	Z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, p))
	Z2 := new(big.Int).Add(beta, new(big.Int).Mul(e, q))
	W1 := new(big.Int).Add(x, new(big.Int).Mul(e, mu))
	W2 := new(big.Int).Add(y, new(big.Int).Mul(e, nu))
	V := new(big.Int).Add(r, new(big.Int).Mul(e, RhoTilde))

	return &NoSmallFactorProof{P, Q, A, B, T, Rho, Z1, Z2, W1, W2, V}
}

func NoSmallFactorVerify(N *big.Int, proof *NoSmallFactorProof, ped *pedersen.PedersenParameters) bool {
	Ntilde := ped.Ntilde
	Nsqrt := new(big.Int).Sqrt(N)

	e := crypto.SHA256Int(N, proof.P, proof.Q, proof.A, proof.B, proof.T, proof.Rho)
	e = new(big.Int).Mod(e, curve.N)

	R, _ := ped.Commit(N, proof.Rho)

	// check commit(Z1, W1) = A * P^e mod Ntilde
	left0, _ := ped.Commit(proof.Z1, proof.W1)
	right0 := new(big.Int).Mod(new(big.Int).Mul(proof.A, new(big.Int).Exp(proof.P, e, Ntilde)), Ntilde)
	if left0.Cmp(right0) != 0 {
		return false
	}

	// check commit(Z2, W2) = B * Q^e mod Ntilde
	left1, _ := ped.Commit(proof.Z2, proof.W2)
	right1 := new(big.Int).Mod(new(big.Int).Mul(proof.B, new(big.Int).Exp(proof.Q, e, Ntilde)), Ntilde)
	if left1.Cmp(right1) != 0 {
		return false
	}

	// check Q^Z1 * ped.T^V = T * R^e mod Ntilde
	left2 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(proof.Q, proof.Z1, Ntilde), new(big.Int).Exp(ped.T, proof.V, Ntilde)), Ntilde)
	right2 := new(big.Int).Mod(new(big.Int).Mul(proof.T, new(big.Int).Exp(R, e, Ntilde)), Ntilde)
	if left2.Cmp(right2) != 0 {
		return false
	}

	// range check
	rangeLimit := new(big.Int).Mul(new(big.Int).Lsh(one, uint(L_NSF+Epsilon_NSF)), Nsqrt)
	if proof.Z1.Cmp(rangeLimit) == 1 || proof.Z2.Cmp(rangeLimit) == 1 {
		return false
	}

	return true
}
