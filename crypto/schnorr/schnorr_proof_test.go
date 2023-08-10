package schnorr

import (
	"encoding/json"
	"fmt"
	"math/big"
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

func TestProofFaulty(t *testing.T) {
	forbidden := big.NewInt(0)
	infinity_point := &curves.ECPoint{Curve: secp256k1.S256(),
		X: big.NewInt(0), Y: big.NewInt(1)}
	X := &curves.ECPoint{Curve: secp256k1.S256(),
		X: big.NewInt(0), Y: big.NewInt(1)}
	fmt.Println("infinity_point =", infinity_point)
	fmt.Println("X =", X)
	proof := &Proof{
		R: infinity_point,
		S: forbidden,
	}
	res := Verify(proof, X)
	fmt.Println("TestProofFaulty:", res)
}

func TestProof_MarshalJSON(t *testing.T) {
	point, _ := curves.EcdsaPubKeyToPoint("0220dcc94db44d846a174b10765bbc2ea916988d098598eb812aaddd5c7378f29d")
	fmt.Println(point)
	proof := Proof{
		R: point,
		S: big.NewInt(100000),
	}

	bytes, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(bytes))

	var proof1 Proof
	if err = json.Unmarshal(bytes, &proof1); err != nil {
		t.Fatal(err)
	}
	fmt.Println(*proof1.R, proof.S)
}
