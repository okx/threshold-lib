package keygen

import (
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
	"math/big"
)

var (
	curve = btcec.S256()
)

type P1Data struct {
	E_x1      *big.Int // paillier encrypt x1
	Proof     *schnorr.Proof
	PaiPubKey *paillier.PublicKey // paillier public key
	X1        *curves.ECPoint
	NIZKProof []string
}

// P1 after dkg, prepare for 2-party signature, P1 send encrypt x1 to P2
// paillier key pair generation is time-consuming, generated in advance, encrypted storage?
func P1(share1 *big.Int, paiPriKey *paillier.PrivateKey, from, to int) (*tss.Message, error) {
	// lagrangian interpolation x1
	x1 := vss.CalLagrangian(curve, big.NewInt(int64(from)), share1, []*big.Int{big.NewInt(int64(from)), big.NewInt(int64(to))})
	paiPubKey := &paiPriKey.PublicKey
	// paillier encrypt x1
	E_x1, err := paiPubKey.Encrypt(x1)
	if err != nil {
		return nil, err
	}
	// schnorr prove x1
	X1 := curves.ScalarToPoint(curve, x1)
	proof, err := schnorr.Prove(x1, X1)
	if err != nil {
		return nil, err
	}
	nizkProof, err := paillier.NIZKProof(paiPriKey.N, paiPriKey.Phi)
	if err != nil {
		return nil, err
	}
	p1Data := P1Data{
		E_x1:      E_x1,
		Proof:     proof,
		PaiPubKey: paiPubKey,
		X1:        X1,
		NIZKProof: nizkProof,
	}
	bytes, err := json.Marshal(p1Data)
	if err != nil {
		return nil, err
	}
	message := &tss.Message{
		From: from,
		To:   to,
		Data: string(bytes),
	}
	return message, nil
}

type P2SaveData struct {
	From      int
	To        int
	E_x1      *big.Int
	PaiPubKey *paillier.PublicKey
	X2        *big.Int
}

// P2 after dkg, prepare for 2-party signature, P2 receives encrypt x1 and paillier public key from P1
func P2(share2 *big.Int, publicKey *curves.ECPoint, msg *tss.Message, from, to int) (*P2SaveData, error) {
	if msg.From != from || msg.To != to {
		return nil, fmt.Errorf("message mismatch")
	}
	p1Data := P1Data{}
	err := json.Unmarshal([]byte(msg.Data), &p1Data)
	if err != nil {
		return nil, err
	}
	// lagrangian interpolation x2, x = x1 + x2
	x2 := vss.CalLagrangian(curve, big.NewInt(int64(to)), share2, []*big.Int{big.NewInt(int64(from)), big.NewInt(int64(to))})
	X2 := curves.ScalarToPoint(curve, x2)
	ecPoint, err := X2.Add(p1Data.X1)
	if err != nil {
		return nil, err
	}
	if !ecPoint.Equals(publicKey) {
		return nil, fmt.Errorf("error message, public keys are not equal")
	}
	verify := schnorr.Verify(p1Data.Proof, p1Data.X1)
	if !verify {
		return nil, fmt.Errorf("schnorr signature verification error")
	}
	// checking paillier keys correct size
	bitlen := p1Data.PaiPubKey.N.BitLen()
	if bitlen != paillier.PrimeBits && bitlen != paillier.PrimeBits-1 {
		return nil, fmt.Errorf("invalid paillier keys")
	}
	nizkVerify := paillier.NIZKVerify(p1Data.PaiPubKey.N, p1Data.NIZKProof)
	if !nizkVerify {
		return nil, fmt.Errorf("paillier public key error")
	}
	// P2 additional save key information
	p2SaveData := &P2SaveData{
		From:      from,
		To:        to,
		E_x1:      p1Data.E_x1,
		X2:        x2,
		PaiPubKey: p1Data.PaiPubKey,
	}
	return p2SaveData, nil
}
