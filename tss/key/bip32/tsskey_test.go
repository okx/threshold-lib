package bip32

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
)

func TestTssKey(t *testing.T) {
	curve := edwards.Edwards()
	x := crypto.RandomNum(curve.N)
	X := curves.ScalarToPoint(curve, x)
	chaincode := hex.EncodeToString([]byte("chaincode"))

	tssKey, _ := NewTssKey(x, X, chaincode)
	// 	/protocol/coinType/index
	tssKey, _ = tssKey.NewChildKey(0)
	tssKey, _ = tssKey.NewChildKey(0)
	tssKey, _ = tssKey.NewChildKey(0)
	fmt.Println("child publicKey: ", tssKey.PublicKey())
	fmt.Println("child key share: ", tssKey.ShareI())
	fmt.Println("privateKey offset: ", tssKey.PrivateKeyOffset())
	childKey := new(big.Int).Mod(new(big.Int).Add(x, tssKey.PrivateKeyOffset()), curve.N)
	fmt.Println("child key share: ", childKey)
}

func TestTssKey_cmp(t *testing.T) {
	curve := secp256k1.S256()
	x := crypto.RandomNum(curve.N)
	X := curves.ScalarToPoint(curve, x)
	chaincode := hex.EncodeToString([]byte("chaincode"))

	tssKey, _ := NewTssKey(nil, X, chaincode)
	fmt.Println(tssKey)
	tssKey, _ = tssKey.NewChildKey(45)
	fmt.Println(tssKey)

	x_new := new(big.Int).Add(x, tssKey.PrivateKeyOffset())
	X_new := curves.ScalarToPoint(curve, x_new)
	fmt.Println(tssKey.publicKey)
	fmt.Println(X_new)
}
