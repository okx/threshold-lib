package commitment

import (
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
)

func TestCommit(t *testing.T) {
	x := crypto.RandomNum(secp256k1.S256().N)
	_, publicKey := secp256k1.PrivKeyFromBytes(x.Bytes())

	cmt := NewCommitment(publicKey.X, publicKey.Y)
	fmt.Println(cmt)

	verify := cmt.Verify()
	fmt.Println(verify)

}
