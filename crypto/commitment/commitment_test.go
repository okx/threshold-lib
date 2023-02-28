package commitment

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/okx/threshold-lib/crypto"
	"testing"
)

func TestCommit(t *testing.T) {
	x := crypto.RandomNum(btcec.S256().N)
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), x.Bytes())

	cmt := NewCommitment(publicKey.X, publicKey.Y)
	fmt.Println(cmt)

	verify := cmt.Verify()
	fmt.Println(verify)

}
