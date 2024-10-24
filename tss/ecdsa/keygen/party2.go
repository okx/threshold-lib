package keygen

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/crypto/pedersen"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/crypto/zkp"
	"github.com/okx/threshold-lib/tss"
)

type P2SaveData struct {
	From      int
	To        int
	E_x1      *big.Int
	PaiPubKey *paillier.PublicKey
	X2        *big.Int
	Ped1      *pedersen.PedersenParameters
	Ped2      *pedersen.PedersenParameters
}

// P2 after dkg, prepare for 2-party signature, P2 receives encrypt x1 and paillier public key from P1
func P2(share2 *big.Int, publicKey *curves.ECPoint, msg *tss.Message, from, to int, ped2 *pedersen.PedersenParameters) (*P2SaveData, error) {
	if msg.From != from || msg.To != to {
		return nil, fmt.Errorf("message mismatch")
	}
	p1Data := &P1Data{}
	err := json.Unmarshal([]byte(msg.Data), p1Data)
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

	err = zkp.PaillierBlumVerify(p1Data.PaiPubKey.N, p1Data.BlumProof)
	if err != nil {
		return nil, fmt.Errorf("Blum proof verify fail due to error [%w]. ", err)
	}
	ok := zkp.NoSmallFactorVerify(p1Data.PaiPubKey.N, p1Data.NoSmallFactorProof, ped2)
	if !ok {
		return nil, fmt.Errorf("No small factor verify fail. ")
	}

	h1i, h2i, NTildei := p1Data.Ped.T, p1Data.Ped.S, p1Data.Ped.Ntilde
	// zkp DlnProof verify
	ok = zkp.DlnVerify(p1Data.DlnProof1, h1i, h2i, NTildei)
	if !ok {
		return nil, fmt.Errorf("DlnProof1 verify fail")
	}
	ok = zkp.DlnVerify(p1Data.DlnProof2, h2i, h1i, NTildei)
	if !ok {
		return nil, fmt.Errorf("DlnProof2 verify fail")
	}

	ok = zkp.GroupElementPaillierEncryptionRangeVerify(p1Data.X1RangeProof, ped2)
	if !ok {
		return nil, fmt.Errorf("Group Element Paillier Encryption Range Proof fail")
	}
	// P2 additional save key information
	p2SaveData := &P2SaveData{
		From:      from,
		To:        to,
		E_x1:      p1Data.E_x1,
		X2:        x2,
		PaiPubKey: p1Data.PaiPubKey,
		Ped1:      p1Data.Ped,
		Ped2:      ped2,
	}
	return p2SaveData, nil
}
