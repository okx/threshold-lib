package reshare

import (
	"crypto/elliptic"
	"fmt"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/key/dkg"
	"testing"
)

func TestRefresh(t *testing.T) {
	curve := edwards.Edwards()
	p1Data, p2Data, p3Data := KeyGen(curve)
	// Reset private key share by 1, 3
	devoteList := [2]int{1, 3}

	refresh1 := NewRefresh(1, 3, devoteList, p1Data.ShareI, p1Data.PublicKey)
	refresh2 := NewRefresh(2, 3, devoteList, nil, p2Data.PublicKey)
	refresh3 := NewRefresh(3, 3, devoteList, p3Data.ShareI, p3Data.PublicKey)

	msgs1_1, _ := refresh1.DKGStep1()
	msgs2_1, _ := refresh2.DKGStep1()
	msgs3_1, _ := refresh3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, _ := refresh1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := refresh2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := refresh3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}

	p1SaveData, _ := refresh1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := refresh2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := refresh3.DKGStep3(msgs3_3_in)

	fmt.Println("refresh1", p1SaveData, p1SaveData.PublicKey)
	fmt.Println("refresh2", p2SaveData, p2SaveData.PublicKey)
	fmt.Println("refresh3", p3SaveData, p3SaveData.PublicKey)

}

func KeyGen(curve elliptic.Curve) (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
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
