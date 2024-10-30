package sign

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/stretchr/testify/require"

	"testing"

	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/key/bip32"
	"github.com/okx/threshold-lib/tss/key/dkg"
)

func TestEcdsaSign(t *testing.T) {
	p1Data, p2Data, _ := KeyGen()

	fmt.Println("=========2/2 keygen==========")
	paiPrivate, _, _ := paillier.NewKeyPair(8)

	p1PreParamsAndProof := keygen.GeneratePreParamsWithDlnProof() // this step should be locally done by P1

	// this step should be locally done by P2. To save time, we assume both setup are the same.
	p2PreParamsAndProof := &keygen.PreParamsWithDlnProof{
		Params: p1PreParamsAndProof.Params,
		Proof:  p1PreParamsAndProof.Proof,
	}

	p1Dto, E_x1, _ := keygen.P1(p1Data.ShareI, paiPrivate, p1Data.Id, p2Data.Id, p1PreParamsAndProof, p2PreParamsAndProof.PedersonParameters(), p2PreParamsAndProof.Proof)
	publicKey, _ := curves.NewECPoint(curve, p2Data.PublicKey.X, p2Data.PublicKey.Y)
	p2SaveData, err := keygen.P2(p2Data.ShareI, publicKey, p1Dto, p1Data.Id, p2Data.Id, p2PreParamsAndProof.PedersonParameters())
	require.NoError(t, err)
	fmt.Println(p2SaveData, err)

	fmt.Println("=========bip32==========")
	tssKey, err := bip32.NewTssKey(p2SaveData.X2, p2Data.PublicKey, p2Data.ChainCode)
	tssKey, err = tssKey.NewChildKey(996)
	x2 := tssKey.ShareI()
	pubKey := &ecdsa.PublicKey{Curve: curve, X: tssKey.PublicKey().X, Y: tssKey.PublicKey().Y}

	fmt.Println("=========2/2 sign==========")
	hash := sha256.New()
	hash.Write([]byte("hello"))
	message := hash.Sum(nil)

	p1 := NewP1(pubKey, hex.EncodeToString(message), paiPrivate, E_x1, p1PreParamsAndProof.PedersonParameters())
	p2 := NewP2(x2, p2SaveData.E_x1, pubKey, p2SaveData.PaiPubKey, hex.EncodeToString(message), p2SaveData.Ped1)

	commit, err := p1.Step1()
	require.NoError(t, err)
	bobProof, R2, err := p2.Step1(commit)
	require.NoError(t, err)

	proof, cmtD, _ := p1.Step2(bobProof, R2)
	E_k2_h_xr, affine_proof, err := p2.Step2(cmtD, proof)
	require.NoError(t, err)

	r, s, err := p1.Step3(E_k2_h_xr, affine_proof)
	require.NoError(t, err)
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

	return p1SaveData, p2SaveData, p3SaveData
}
