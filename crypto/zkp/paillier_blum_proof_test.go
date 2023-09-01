package zkp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/okx/threshold-lib/crypto"
)

func TestPaillierBlumProof(t *testing.T) {
	fmt.Println("----------------------- TestPaillierBlumProof --------------------------")
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

	proof := PaillierBlumProve(N, p, q)
	verify := PaillierBlumVerify(N, proof)
	fmt.Println("PaillierBlumProof of honest prover:", verify)

	p, _ = rand.Prime(rand.Reader, bits)
	q, _ = rand.Prime(rand.Reader, bits)
	fmt.Println("Pi % 4:", new(big.Int).Mod(p, big.NewInt(4)))
	fmt.Println("Qi % 4:", new(big.Int).Mod(q, big.NewInt(4)))

	N = new(big.Int).Mul(p, q)
	proof = PaillierBlumProve(N, p, q)
	verify = PaillierBlumVerify(N, proof)
	fmt.Println("PaillierBlumProof of malicious prover:", verify)

}
