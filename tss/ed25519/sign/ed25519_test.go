package sign

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/key/dkg"
	"math/big"
	"testing"
)

func TestEd25519(t *testing.T) {
	for i := 0; i < 10; i++ {
		p1Data, p2Data, p3Data := keyGen(curve)

		hash := sha256.New()
		hash.Write([]byte("hello"))
		message := hash.Sum(nil)
		publicKey := edwards.NewPublicKey(p1Data.PublicKey.X, p1Data.PublicKey.Y)

		sign_p1_p2(p1Data, p2Data, publicKey, message)
		sign_p1_p3(p1Data, p3Data, publicKey, message)
		sign_p2_p3(p2Data, p3Data, publicKey, message)
	}
}

func sign_p1_p2(p1Data, p2Data *tss.KeyStep3Data, publicKey *edwards.PublicKey, message []byte) {
	fmt.Println("=========sign_p1_p2========")
	partList := []int{1, 2}
	p1 := NewEd25519Sign(1, 2, partList, p1Data.ShareI, publicKey, hex.EncodeToString(message))
	p2 := NewEd25519Sign(2, 2, partList, p2Data.ShareI, publicKey, hex.EncodeToString(message))

	p1Step1, _ := p1.SignStep1()
	p2Step1, _ := p2.SignStep1()

	p1Step2, _ := p1.SignStep2([]*tss.Message{p2Step1[1]})
	p2Step2, _ := p2.SignStep2([]*tss.Message{p1Step1[2]})

	si_1, r, _ := p1.SignStep3([]*tss.Message{p2Step2[1]})
	fmt.Println("si_1: ", si_1, r)
	si_2, r, _ := p2.SignStep3([]*tss.Message{p1Step2[2]})
	fmt.Println("si_2: ", si_2, r)

	s := new(big.Int).Add(si_1, si_2)
	signature := edwards.NewSignature(r, s)
	ret := signature.Verify(message, publicKey)
	fmt.Println("Verify: ", ret)
}

func sign_p1_p3(p1Data, p3Data *tss.KeyStep3Data, publicKey *edwards.PublicKey, message []byte) {
	fmt.Println("=========sign_p1_p3========")
	partList := []int{1, 3}
	p1 := NewEd25519Sign(1, 2, partList, p1Data.ShareI, publicKey, hex.EncodeToString(message))
	p3 := NewEd25519Sign(3, 2, partList, p3Data.ShareI, publicKey, hex.EncodeToString(message))

	p1Step1, _ := p1.SignStep1()
	p3Step1, _ := p3.SignStep1()

	p1Step2, _ := p1.SignStep2([]*tss.Message{p3Step1[1]})
	p3Step2, _ := p3.SignStep2([]*tss.Message{p1Step1[3]})

	si_1, r, _ := p1.SignStep3([]*tss.Message{p3Step2[1]})
	fmt.Println("si_1: ", si_1, r)
	si_3, r, _ := p3.SignStep3([]*tss.Message{p1Step2[3]})
	fmt.Println("si_3: ", si_3, r)

	s := new(big.Int).Add(si_1, si_3)
	signature := edwards.NewSignature(r, s)
	ret := signature.Verify(message, publicKey)
	fmt.Println("Verify: ", ret)
}

func sign_p2_p3(p2Data, p3Data *tss.KeyStep3Data, publicKey *edwards.PublicKey, message []byte) {
	fmt.Println("=========sign_p2_p3========")
	partList := []int{2, 3}
	p2 := NewEd25519Sign(2, 2, partList, p2Data.ShareI, publicKey, hex.EncodeToString(message))
	p3 := NewEd25519Sign(3, 2, partList, p3Data.ShareI, publicKey, hex.EncodeToString(message))

	p2Step1, _ := p2.SignStep1()
	p3Step1, _ := p3.SignStep1()

	p2Step2, _ := p2.SignStep2([]*tss.Message{p3Step1[2]})
	p3Step2, _ := p3.SignStep2([]*tss.Message{p2Step1[3]})

	si_2, r, _ := p2.SignStep3([]*tss.Message{p3Step2[2]})
	fmt.Println("si_2: ", si_2, r)
	si_3, r, _ := p3.SignStep3([]*tss.Message{p2Step2[3]})
	fmt.Println("si_3: ", si_3, r)

	s := new(big.Int).Add(si_3, si_2)
	signature := edwards.NewSignature(r, s)
	ret := signature.Verify(message, publicKey)
	fmt.Println("Verify: ", ret)
}

func keyGen(curve elliptic.Curve) (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
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
