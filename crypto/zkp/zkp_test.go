package zkp

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"math/big"
	"testing"
)

func TestZkpProof(t *testing.T) {
	// -----------------------GeneratePreParams-------------------------------
	var values = make(chan *big.Int)
	var quit = make(chan int)
	var Pi, Qi *big.Int
	for Pi == Qi {
		for i := 0; i < 4; i++ {
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
	curve := secp256k1.S256()
	G := curves.ScalarToPoint(curve, big.NewInt(1))
	_, paiPub, _ := paillier.NewKeyPair(8)

	// DlnProof
	dlnProof1 := NewDlnProve(h1i, h2i, alpha, pi, qi, NTildei)
	dlnProof2 := NewDlnProve(h2i, h1i, beta, pi, qi, NTildei)
	verify := DlnVerify(dlnProof1, h1i, h2i, NTildei)
	fmt.Println(verify)
	verify = DlnVerify(dlnProof2, h2i, h1i, NTildei)
	fmt.Println(verify)

	x := crypto.RandomNum(curve.N)
	X := curves.ScalarToPoint(curve, x)
	Ex, r, _ := paiPub.Encrypt(x)

	// PDLwSlackProof
	pdlWSlackWitness := &PDLwSlackWitness{
		X: x,
		R: r,
	}
	pdlWSlackStatement := &PDLwSlackStatement{
		N:          paiPub.N,
		CipherText: Ex,
		Q:          X,
		G:          G,
		H1:         h1i,
		H2:         h2i,
		NTilde:     NTildei,
	}
	pdlWSlackPf, _ := NewPDLwSlackProve(pdlWSlackWitness, pdlWSlackStatement)

	verify = PDLwSlackVerify(pdlWSlackPf, pdlWSlackStatement)
	fmt.Println(verify)

	// range proof
	rangeProof, _ := RangeProve(paiPub, NTildei, h1i, h2i, Ex, r, x)
	verify = RangeVerify(rangeProof, paiPub, NTildei, h1i, h2i, Ex)
	fmt.Println(verify)
}
