package zkp

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/pedersen"
)

func TestAffGProof(t *testing.T) {
	// -----------------------GeneratePreParams-------------------------------
	fmt.Println("----------------------- TestAffGProof ---------------------------------")
	pesersen, _ := pedersen.NewPedersenParameters(8)
	// const bits = 512
	const bits = 1024

	concurrency := 4
	var values = make(chan *big.Int, concurrency)
	var p, q *big.Int
	for p == q {
		var quit = make(chan int)
		for i := 0; i < concurrency; i++ {
			go crypto.GenerateSafePrime(bits, values, quit)
		}
		p, q = <-values, <-values
		close(quit)
	}
	N := new(big.Int).Mul(p, q)
	N2 := new(big.Int).Mul(N, N)

	rangeL0 := new(big.Int).Lsh(one, uint(L0_Aff_G))
	rangeL1 := new(big.Int).Lsh(one, uint(L1_Aff_G))

	x := crypto.RandomNum(rangeL0)
	y := crypto.RandomNum(rangeL1)
	rho := crypto.RandomNum(N)

	witness := &AffGWitness{
		X:   x,
		Y:   y,
		Rho: rho,
	}

	// C is an ciphertext of an Paillier encryption of a secret
	C := crypto.RandomNum(N2)

	// D = C^x * (1+N)^y * rho^N mod N^2
	D := new(big.Int).Exp(C, x, N2)
	D = new(big.Int).Mod(new(big.Int).Mul(D, new(big.Int).Exp(new(big.Int).Add(one, N), y, N2)), N2)
	D = new(big.Int).Mod(new(big.Int).Mul(D, new(big.Int).Exp(rho, N, N2)), N2)

	X := curves.ScalarToPoint(curve, x)
	Y := curves.ScalarToPoint(curve, y)

	st := &AffGStatement{
		N: N,
		C: C,
		D: D,
		X: X,
		Y: Y,
	}

	proof := PaillierAffineProve(pesersen, st, witness)
	verify := PaillierAffineVerify(pesersen, proof, st)

	fmt.Println("PaillierAffineProof of honest prover:", verify)

	x = crypto.RandomNum(N)
	witness = &AffGWitness{
		X:   x,
		Y:   y,
		Rho: rho,
	}
	proof = PaillierAffineProve(pesersen, st, witness)
	verify = PaillierAffineVerify(pesersen, proof, st)
	fmt.Println("PaillierAffineProof of malicious prover:", verify)

}
