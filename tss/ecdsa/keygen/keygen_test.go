package keygen

import (
	"fmt"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/key/bip32"
	"github.com/okx/threshold-lib/tss/key/dkg"
	"testing"
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
	paiPriKey, _, _ := paillier.NewKeyPair(8)
	p1Data, _ := P1(p1SaveData.ShareI, paiPriKey, setUp1.DeviceNumber, setUp2.DeviceNumber)
	fmt.Println("p1Data", p1Data)
	publicKey, _ := curves.NewECPoint(curve, p2SaveData.PublicKey.X, p2SaveData.PublicKey.Y)
	p2Data, _ := P2(p2SaveData.ShareI, publicKey, p1Data, setUp1.DeviceNumber, setUp2.DeviceNumber)
	fmt.Println("p2Data", p2Data)

	p1Data, _ = P1(p1SaveData.ShareI, paiPriKey, setUp1.DeviceNumber, setUp3.DeviceNumber)
	fmt.Println("p1Data", p1Data)
	p2Data, _ = P2(p3SaveData.ShareI, publicKey, p1Data, setUp1.DeviceNumber, setUp3.DeviceNumber)
	fmt.Println("p2Data", p2Data)

	fmt.Println("=========bip32==========")
	tssKey, _ := bip32.NewTssKey(p1SaveData.ShareI, p1SaveData.PublicKey, p1SaveData.ChainCode)
	tssKey, _ = tssKey.NewChildKey(996)
	fmt.Println(tssKey.PublicKey())

	tssKey, _ = bip32.NewTssKey(p2SaveData.ShareI, p2SaveData.PublicKey, p2SaveData.ChainCode)
	tssKey, _ = tssKey.NewChildKey(996)
	fmt.Println(tssKey.PublicKey())

}
