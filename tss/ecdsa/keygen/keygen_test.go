package keygen

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.okg.com/wallet-sign-core/crypto-mpc/crypto/curves"
	"gitlab.okg.com/wallet-sign-core/crypto-mpc/crypto/paillier"
	"gitlab.okg.com/wallet-sign-core/crypto-mpc/tss"
	"gitlab.okg.com/wallet-sign-core/crypto-mpc/tss/key/bip32"
	"gitlab.okg.com/wallet-sign-core/crypto-mpc/tss/key/dkg"
)

func TestKeyGen(t *testing.T) {
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

	fmt.Println("=========2/2 keygen==========")

	// 1-->2   1--->3
	paiPriKey, _, err := paillier.NewKeyPair(8)
	require.NoError(t, err)
	p1PreParamsAndProof := GeneratePreParamsWithDlnProof() // this step should be locally done by P1

	// this step should be locally done by P2. To save time, we assume both setup are the same.
	p2PreParamsAndProof := &PreParamsWithDlnProof{
		Params: p1PreParamsAndProof.Params,
		Proof:  p1PreParamsAndProof.Proof,
	}

	p1Data, _, err := P1(p1SaveData.ShareI, paiPriKey, setUp1.DeviceNumber, setUp2.DeviceNumber, p1PreParamsAndProof, p2PreParamsAndProof.PedersonParameters(), p2PreParamsAndProof.Proof)

	require.NoError(t, err)
	fmt.Println("p1Data", p1Data)
	publicKey, _ := curves.NewECPoint(curve, p2SaveData.PublicKey.X, p2SaveData.PublicKey.Y)
	p2Data, err := P2(p2SaveData.ShareI, publicKey, p1Data, setUp1.DeviceNumber, setUp2.DeviceNumber, p2PreParamsAndProof.PedersonParameters())
	require.NoError(t, err)
	fmt.Println("p2Data", p2Data)

	p1Data, _, err = P1(p1SaveData.ShareI, paiPriKey, setUp1.DeviceNumber, setUp3.DeviceNumber, p1PreParamsAndProof, p2PreParamsAndProof.PedersonParameters(), p2PreParamsAndProof.Proof)
	require.NoError(t, err)
	fmt.Println("p1Data", p1Data)
	p2Data, err = P2(p3SaveData.ShareI, publicKey, p1Data, setUp1.DeviceNumber, setUp3.DeviceNumber, p2PreParamsAndProof.PedersonParameters())
	require.NoError(t, err)
	fmt.Println("p2Data", p2Data)

	fmt.Println("=========bip32==========")
	tssKey, err := bip32.NewTssKey(p1SaveData.ShareI, p1SaveData.PublicKey, p1SaveData.ChainCode)
	require.NoError(t, err)
	tssKey, err = tssKey.NewChildKey(996)
	require.NoError(t, err)
	fmt.Println(tssKey.PublicKey())

	tssKey, err = bip32.NewTssKey(p2SaveData.ShareI, p2SaveData.PublicKey, p2SaveData.ChainCode)
	require.NoError(t, err)
	tssKey, err = tssKey.NewChildKey(996)
	require.NoError(t, err)
	fmt.Println(tssKey.PublicKey())

}
