package schnorr

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"testing"
)

func TestProof(t *testing.T) {
	q := btcec.S256().N
	x := crypto.RandomNum(q)
	X := curves.ScalarToPoint(btcec.S256(), x)
	proof, _ := Prove(x, X)

	res := Verify(proof, X)
	fmt.Println(res)
}
