package sign

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"

	"testing"

	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/key/bip32"
	"github.com/okx/threshold-lib/tss/key/dkg"
)

func TestTwoSign(t *testing.T) {
	N := curve.N
	hash := sha256.New()
	message := hash.Sum([]byte("hello"))

	x1 := crypto.RandomNum(N)
	x2 := crypto.RandomNum(N)
	_, publicKey := secp256k1.PrivKeyFromBytes(new(big.Int).Add(x1, x2).Bytes())

	paiPri, paiPub, _ := paillier.NewKeyPair(8)

	p1 := NewP1(publicKey.ToECDSA(), hex.EncodeToString(message), paiPri)
	E_x1, _ := paiPub.Encrypt(x1)
	p2 := NewP2(x2, E_x1, publicKey.ToECDSA(), paiPub, hex.EncodeToString(message))

	commit, _ := p1.Step1()
	bobProof, R2, _ := p2.Step1(commit)

	proof, cmtD, _ := p1.Step2(bobProof, R2)
	E_k2_h_xr, _ := p2.Step2(cmtD, proof)

	r, s, _ := p1.Step3(E_k2_h_xr)
	fmt.Println(r, s)
}

func TestEcdsaSign(t *testing.T) {
	p1Data, p2Data, _ := KeyGen()

	fmt.Println("=========2/2 keygen==========")
	paiPrivate, _, _ := paillier.NewKeyPair(8)
	p1Dto, _ := keygen.P1(p1Data.ShareI, paiPrivate, p1Data.Id, p2Data.Id)
	publicKey, _ := curves.NewECPoint(curve, p2Data.PublicKey.X, p2Data.PublicKey.Y)
	p2SaveData, err := keygen.P2(p2Data.ShareI, publicKey, p1Dto, p1Data.Id, p2Data.Id)
	fmt.Println(p2SaveData, err)

	fmt.Println("=========bip32==========")
	tssKey, err := bip32.NewTssKey(p2SaveData.X2, p2Data.PublicKey, p2Data.ChainCode)
	tssKey, err = tssKey.NewChildKey(996)
	x2 := tssKey.ShareI()
	pubKey := &ecdsa.PublicKey{Curve: curve, X: tssKey.PublicKey().X, Y: tssKey.PublicKey().Y}

	fmt.Println("=========2/2 sign==========")
	hash := sha256.New()
	message := hash.Sum([]byte("hello"))

	p1 := NewP1(pubKey, hex.EncodeToString(message), paiPrivate)
	p2 := NewP2(x2, p2SaveData.E_x1, pubKey, p2SaveData.PaiPubKey, hex.EncodeToString(message))

	commit, _ := p1.Step1()
	bobProof, R2, _ := p2.Step1(commit)

	proof, cmtD, _ := p1.Step2(bobProof, R2)
	E_k2_h_xr, _ := p2.Step2(cmtD, proof)

	r, s, _ := p1.Step3(E_k2_h_xr)
	fmt.Println(r, s)
}

func KeyGen() (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
	setUp1 := dkg.NewSetUp(1, 3, curve)
	setUp2 := dkg.NewSetUp(2, 3, curve)
	setUp3 := dkg.NewSetUp(3, 3, curve)

	msgs1_1, _ := setUp1.DKGStep1()
	msgs2_1, _ := setUp2.DKGStep1()
	msgs3_1, _ := setUp3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, _ := setUp1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := setUp2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := setUp3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}

	p1SaveData, _ := setUp1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := setUp2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := setUp3.DKGStep3(msgs3_3_in)

	fmt.Println("setUp1", p1SaveData, p1SaveData.PublicKey)
	fmt.Println("setUp2", p2SaveData, p2SaveData.PublicKey)
	fmt.Println("setUp3", p3SaveData, p3SaveData.PublicKey)
	return p1SaveData, p2SaveData, p3SaveData
}
