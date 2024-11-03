package zkp

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/okx/threshold-lib/crypto"
)

func TestZkpProof(t *testing.T) {
	// -----------------------GeneratePreParams-------------------------------
	concurrency := 4
	var values = make(chan *big.Int, concurrency)
	var Pi, Qi *big.Int
	for Pi == Qi {
		var quit = make(chan int)
		for i := 0; i < concurrency; i++ {
			go crypto.GenerateSafePrime(1024, values, quit)
		}
		Pi, Qi = <-values, <-values
		close(quit)
	}

	NTildei := new(big.Int).Mul(Pi, Qi)
	// Compute pi = (Pi-1)/2, qi = (Qi-1)/2
	pi := new(big.Int).Rsh(Pi, 1)
	qi := new(big.Int).Rsh(Qi, 1)

	pq := new(big.Int).Mul(pi, qi)
	f1 := crypto.RandomNum(NTildei)
	alpha := crypto.RandomNum(NTildei)
	beta := new(big.Int).ModInverse(alpha, pq)

	// h1i = f^2 mod tildeNi, h2i = h1i^alpha mod tildeNi
	h1i := new(big.Int).Mod(new(big.Int).Mul(f1, f1), NTildei)
	h2i := new(big.Int).Exp(h1i, alpha, NTildei)

	// ------------------------------------------------------

	// DlnProof
	dlnProof1 := NewDlnProve(h1i, h2i, alpha, pi, qi, NTildei)
	dlnProof2 := NewDlnProve(h2i, h1i, beta, pi, qi, NTildei)
	verify := DlnVerify(dlnProof1, h1i, h2i, NTildei)
	fmt.Println(verify)
	verify = DlnVerify(dlnProof2, h2i, h1i, NTildei)
	fmt.Println(verify)
}
