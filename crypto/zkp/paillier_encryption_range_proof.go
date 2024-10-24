package zkp

import (
	"math/big"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/crypto/pedersen"
)

type PaillierEncryptionRangeProof struct {
	N0, C, Z1, Z2, Z3 *big.Int
	S, A, D           *big.Int
	SecurityParams    *SecurityParameter
	L                 uint
}

func NewPaillierEncryptionRangeProof(N0, C, x, rho *big.Int, l uint, ped *pedersen.PedersenParameters, security_params *SecurityParameter) *PaillierEncryptionRangeProof {
	Ntilde := ped.Ntilde
	range_l_plus_epsilon := new(big.Int).Lsh(one, l+security_params.Epsilon)
	range_l := new(big.Int).Lsh(one, l)
	range_q := new(big.Int).Lsh(one, security_params.Q_bitlen)

	alpha := crypto.RandomNum(range_l_plus_epsilon)
	mu := crypto.RandomNum(new(big.Int).Mul(range_l, Ntilde))
	r := crypto.RandomNum(N0)
	gamma := crypto.RandomNum(new(big.Int).Mul(range_l_plus_epsilon, Ntilde))

	S, _ := ped.Commit(x, mu)
	pubKey := &paillier.PublicKey{N: N0}
	A, _ := pubKey.EncryptWithR(alpha, r)
	D, _ := ped.Commit(alpha, gamma)

	e := crypto.SHA256Int(S, A, D, N0, C)
	e = new(big.Int).Mod(e, range_q)

	// z1 = alpha + ex
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, x))
	// z2 = r*rho^e mod N0
	z2 := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, N0))
	z2 = new(big.Int).Mod(z2, N0)
	// z3 = gamma +e*mu
	z3 := new(big.Int).Add(gamma, new(big.Int).Mul(e, mu))

	return &PaillierEncryptionRangeProof{
		N0:             N0,
		C:              C,
		Z1:             z1,
		Z2:             z2,
		Z3:             z3,
		S:              S,
		A:              A,
		D:              D,
		SecurityParams: security_params,
		L:              l,
	}
}

func GroupElementPaillierEncryptionRangeVerify(proof *PaillierEncryptionRangeProof, ped *pedersen.PedersenParameters) bool {
	// equality check
	z1 := proof.Z1
	z2 := proof.Z2
	z3 := proof.Z3
	range_q := new(big.Int).Lsh(one, proof.SecurityParams.Q_bitlen)
	range_l_plus_epsilon := new(big.Int).Lsh(one, proof.L+proof.SecurityParams.Epsilon)

	e := crypto.SHA256Int(proof.S, proof.A, proof.D, proof.N0, proof.C)
	e = new(big.Int).Mod(e, range_q)

	pubKey := paillier.PublicKey{N: proof.N0}
	N0Sqr := new(big.Int).Mul(proof.N0, proof.N0)

	// Equality Check 1: (1 + N0)^z1*z2^N0 = A * C^e mod N0^2
	left, _ := pubKey.EncryptWithR(z1, z2)
	right := new(big.Int).Mul(proof.A, new(big.Int).Exp(proof.C, e, N0Sqr))
	right = new(big.Int).Mod(right, N0Sqr)
	if left.Cmp(right) != 0 {
		return false
	}

	// Equality Check 3: s^z1*t^z3 =D*S^e mod N~
	left, _ = ped.Commit(z1, z3)
	right = new(big.Int).Mul(proof.D, new(big.Int).Exp(proof.S, e, ped.Ntilde))
	right = new(big.Int).Mod(right, ped.Ntilde)
	if left.Cmp(right) != 0 {
		return false
	}

	if !crypto.IsInInterval(z1, range_l_plus_epsilon) {
		return false
	}
	return true
}
