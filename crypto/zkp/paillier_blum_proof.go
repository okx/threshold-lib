package zkp

import (
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto"
)

const Security = 100

type (
	PaillierBlumProof struct {
		W                          *big.Int
		X_arr, A_arr, B_arr, Z_arr []*big.Int
	}
)

var (
	zero = big.NewInt(0)
)

// https://eprint.iacr.org/2020/492.pdf 4.3 Paillier Blum Modulus ZK
func PaillierBlumProve(N, p, q *big.Int) *PaillierBlumProof {
	if N.Cmp(new(big.Int).Mul(p, q)) != 0 {
		return nil
	}

	w := crypto.RandomNum(N)
	for big.Jacobi(w, N) != -1 {
		w = crypto.RandomNum(N)
	}

	// e := crypto.SHA256Int(N, p, q, w)
	y_arr := make([]*big.Int, Security)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	pow := new(big.Int).ModInverse(N, phi)

	X_arr := make([]*big.Int, Security)
	A_arr := make([]*big.Int, Security)
	B_arr := make([]*big.Int, Security)
	Z_arr := make([]*big.Int, Security)

	var err error
	for i := 0; i < Security; i++ {
		y_arr[i] = new(big.Int).Mod(oracle(N, w, i), N)
		X_arr[i], A_arr[i], B_arr[i], err = getQuaticSqrt(N, p, q, w, y_arr[i])
		if err != nil {
			fmt.Println("N should be an odd composite number")
			return nil
		}
		Z_arr[i] = new(big.Int).Exp(y_arr[i], pow, N)
	}

	return &PaillierBlumProof{W: w, X_arr: X_arr, A_arr: A_arr, B_arr: B_arr, Z_arr: Z_arr}
}

func PaillierBlumVerify(N *big.Int, proof *PaillierBlumProof) bool {
	if (new(big.Int).Mod(N, two)).Cmp(zero) == 0 || N.ProbablyPrime(100) {
		fmt.Println("N should be an odd composite number")
		return false
	}

	if proof == nil {
		fmt.Println("Invalid proof")
		return false
	}

	if len(proof.X_arr) != Security || len(proof.A_arr) != Security || len(proof.B_arr) != Security || len(proof.Z_arr) != Security {
		fmt.Println("Invalid proof length")
		return false
	}

	y_arr := make([]*big.Int, Security)
	for i := 0; i < Security; i++ {
		if proof.X_arr[i] == nil || proof.A_arr[i] == nil || proof.B_arr[i] == nil || proof.Z_arr[i] == nil {
			fmt.Println("Invalid value in proof")
			return false
		}
		y_arr[i] = new(big.Int).Mod(oracle(N, proof.W, i), N)

		// assert (z^N = r mod N)
		if new(big.Int).Exp(proof.Z_arr[i], N, N).Cmp(y_arr[i]) != 0 {
			fmt.Println("z^N != r mod N")
			return false
		}
		// c = (-1)^a * w^b * r mod N
		// assert (x^4 = c mod N)
		c := new(big.Int).Exp(new(big.Int).Neg(one), proof.A_arr[i], N)
		c = new(big.Int).Mod(new(big.Int).Mul(c, new(big.Int).Exp(proof.W, proof.B_arr[i], N)), N)
		c = new(big.Int).Mod(new(big.Int).Mul(c, y_arr[i]), N)

		if new(big.Int).Exp(proof.X_arr[i], big.NewInt(4), N).Cmp(c) != 0 {
			fmt.Println("x^4 != c mod N")
			return false
		}
	}

	return true
}

func getQuaticSqrt(N, p, q, w, r *big.Int) (root, a, b *big.Int, err error) {
	flag1 := false
	flag2 := false
	quadratic_root_1 := zero
	quadratic_root_2 := zero

	r_arr := make([]*big.Int, 4)
	r_arr[0] = r
	r_arr[1] = new(big.Int).Mul(r, new(big.Int).Neg(one))
	r_arr[2] = new(big.Int).Mul(r, w)
	r_arr[3] = new(big.Int).Mul(r_arr[2], new(big.Int).Neg(one))

	a1_arr := make([]*big.Int, 4)
	a2_arr := make([]*big.Int, 4)

	for i := 0; i < 4; i++ {
		a1_arr[i] = new(big.Int).Mod(r_arr[i], p)
		a2_arr[i] = new(big.Int).Mod(r_arr[i], q)
	}

	for i := 0; i < 4; i++ {
		flag1 = quadraticResidue(a1_arr[i], p) == 1
		if !flag1 {
			continue
		}

		flag2 = quadraticResidue(a2_arr[i], q) == 1
		if !flag2 {
			continue
		}

		quadratic_root_1 = new(big.Int).ModSqrt(a1_arr[i], p)
		quadratic_root_2 = new(big.Int).ModSqrt(a2_arr[i], q)

		if (i & 0x01) > 0 {
			a = one
		} else {
			a = zero
		}

		if (i & 0x02) > 0 {
			b = one
		} else {
			b = zero
		}
		break
	}

	if !flag2 {
		return nil, nil, nil, fmt.Errorf("No quatic sqrt solution")
	}

	a1_arr[0] = quadratic_root_1
	a1_arr[1] = new(big.Int).Mul(quadratic_root_1, new(big.Int).Neg(one))
	a1_arr[2] = quadratic_root_1
	a1_arr[3] = new(big.Int).Mul(quadratic_root_1, new(big.Int).Neg(one))

	a2_arr[0] = quadratic_root_2
	a2_arr[1] = quadratic_root_2
	a2_arr[2] = new(big.Int).Mul(quadratic_root_2, new(big.Int).Neg(one))
	a2_arr[3] = new(big.Int).Mul(quadratic_root_2, new(big.Int).Neg(one))

	for i := 0; i < 4; i++ {
		flag1 = quadraticResidue(a1_arr[i], p) == 1
		if !flag1 {
			continue
		}
		flag2 = quadraticResidue(a2_arr[i], q) == 1
		if !flag2 {
			continue
		}

		quadratic_root_1 = new(big.Int).ModSqrt(a1_arr[i], p)
		quadratic_root_2 = new(big.Int).ModSqrt(a2_arr[i], q)

		p_inv := new(big.Int).ModInverse(p, q)
		q_inv := new(big.Int).ModInverse(q, p)
		root = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(quadratic_root_1, q), q_inv), N)
		root = new(big.Int).Mod(new(big.Int).Add(root, new(big.Int).Mul(new(big.Int).Mul(quadratic_root_2, p), p_inv)), N)
		return root, a, b, nil
	}
	return nil, nil, nil, fmt.Errorf("No quatic sqrt solution")
}

func quadraticResidue(a, p *big.Int) int {
	temp := new(big.Int).Exp(a, new(big.Int).Div(new(big.Int).Sub(p, one), two), p)
	if temp.Cmp(one) == 0 {
		return 1
	} else if temp.Cmp(new(big.Int).Sub(p, one)) == 0 {
		return -1
	}
	return 0
}

func oracle(N, w *big.Int, i int) *big.Int {
	rnd := new(big.Int).Mul(crypto.SHA512Int(N, w, big.NewInt(int64(4*i))), crypto.SHA512Int(N, w, big.NewInt(int64(4*i+1))))
	rnd = new(big.Int).Mul(rnd, crypto.SHA512Int(N, w, big.NewInt(int64(4*i+2))))
	rnd = new(big.Int).Mul(rnd, crypto.SHA512Int(N, w, big.NewInt(int64(4*i+3))))
	return rnd
}
