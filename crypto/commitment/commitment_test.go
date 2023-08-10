package commitment

import (
	"encoding/json"
	"fmt"
	"math/big"
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

func TestHashCommitment_MarshalJSON(t *testing.T) {
	hcmt := HashCommitment{
		C:   big.NewInt(1),
		Msg: []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)},
	}

	bytes, err := json.Marshal(hcmt)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(bytes))

	var res HashCommitment
	err = json.Unmarshal(bytes, &res)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("C", res.C.Cmp(hcmt.C) == 0)
	for i, bigint := range res.Msg {
		fmt.Printf("Witness[%d]: %v\n", i, hcmt.Msg[i].Cmp(bigint) == 0)
	}
}
