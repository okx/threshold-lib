package curves

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/okx/threshold-lib/crypto"
	"testing"
)

func TestCurve(t *testing.T) {
	curve := btcec.S256()
	x := crypto.RandomNum(curve.N)
	point := ScalarToPoint(curve, x)
	fmt.Println(point)

	ecPoint := point.ScalarMult(x)
	fmt.Println(ecPoint)

	bytes, _ := json.Marshal(ecPoint)
	fmt.Println(string(bytes))
	p := ECPoint{}
	_ = json.Unmarshal(bytes, &p)
	fmt.Println(p)

	add, _ := ecPoint.Add(&p)
	fmt.Println(add)
}

func TestPointToPubKey(t *testing.T) {
	curve := btcec.S256()
	x := crypto.RandomNum(curve.N)
	fmt.Println("private key: ", hex.EncodeToString(x.Bytes()))
	point := ScalarToPoint(curve, x)
	publicKey := btcec.PublicKey{Curve: point.Curve, X: point.X, Y: point.Y}
	fmt.Println("ecdsa publicKey: ", hex.EncodeToString(publicKey.SerializeCompressed()))

	curve2 := edwards.Edwards()
	point2 := ScalarToPoint(curve2, x)
	publicKey2 := edwards.PublicKey{Curve: point2.Curve, X: point2.X, Y: point2.Y}
	fmt.Println("ed25519 publicKey: ", hex.EncodeToString(publicKey2.SerializeCompressed()))
}

func TestPubKeyToPoint(t *testing.T) {
	// ecdsa publicKey:  0220dcc94db44d846a174b10765bbc2ea916988d098598eb812aaddd5c7378f29d
	point, err := EcdsaPubKeyToPoint("0220dcc94db44d846a174b10765bbc2ea916988d098598eb812aaddd5c7378f29d")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(point)
	}

	// ed25519 publicKey:  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
	point2, err := Ed25519PubKeyToPoint("bb10a2166436f1d8d1b8dc18403ed0b254b5d024e4e1b1a62d697803cb1c4379")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(point2)
	}
}
