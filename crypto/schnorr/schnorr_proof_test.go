package schnorr

import (
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
)

func TestProof(t *testing.T) {
	q := secp256k1.S256().N
	x := crypto.RandomNum(q)
	X := curves.ScalarToPoint(secp256k1.S256(), x)
	proof, _ := Prove(x, X)

	res := Verify(proof, X)
	fmt.Println(res)
}
