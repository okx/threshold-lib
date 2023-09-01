package zkp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/okx/threshold-lib/crypto/pedersen"
)

func TestNoSmallFactorProof(t *testing.T) {
	// -----------------------GeneratePreParams-------------------------------
	fmt.Println("----------------------- TestNoSmallFactorProof -------------------------")
	ped, _ := pedersen.NewPedersenParameters(8)
	const bits = 1024

	p, _ := rand.Prime(rand.Reader, bits)
	q, _ := rand.Prime(rand.Reader, bits)
	N := new(big.Int).Mul(p, q)

	proof := NoSmallFactorProve(N, p, q, ped)
	verify := NoSmallFactorVerify(N, proof, ped)
	fmt.Println("NoSmallFactorProof of honest prover:", verify)

	p, _ = rand.Prime(rand.Reader, 16)
	q, _ = rand.Prime(rand.Reader, 2*bits-16)
	N = new(big.Int).Mul(p, q)
	proof = NoSmallFactorProve(N, p, q, ped)
	verify = NoSmallFactorVerify(N, proof, ped)
	fmt.Println("NoSmallFactorProof of malicious prover:", verify)

}
