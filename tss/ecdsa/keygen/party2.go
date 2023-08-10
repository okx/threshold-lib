package keygen

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
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
}

// P2 after dkg, prepare for 2-party signature, P2 receives encrypt x1 and paillier public key from P1
func P2(share2 *big.Int, publicKey *curves.ECPoint, msg *tss.Message, from, to int) (*P2SaveData, error) {
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
	nizkVerify := paillier.NIZKVerify(p1Data.PaiPubKey.N, p1Data.NIZKProof)
	if !nizkVerify {
		return nil, fmt.Errorf("paillier public key error")
	}

	h1i, h2i, NTildei := p1Data.StatementParams.H1, p1Data.StatementParams.H2, p1Data.StatementParams.NTilde
	// zkp DlnProof verify
	ok := zkp.DlnVerify(p1Data.DlnProof1, h1i, h2i, NTildei)
	if !ok {
		return nil, fmt.Errorf("DlnProof1 verify fail")
	}
	ok = zkp.DlnVerify(p1Data.DlnProof2, h2i, h1i, NTildei)
	if !ok {
		return nil, fmt.Errorf("DlnProof2 verify fail")
	}

	// PDLwSlackVerify
	pdlWSlackStatement := &zkp.PDLwSlackStatement{
		N:          p1Data.PaiPubKey.N,
		CipherText: p1Data.E_x1,
		Q:          p1Data.X1,
		G:          G,
		H1:         h1i,
		H2:         h2i,
		NTilde:     NTildei,
	}
	slackVerify := zkp.PDLwSlackVerify(p1Data.PDLwSlackProof, pdlWSlackStatement)
	if !slackVerify {
		return nil, fmt.Errorf("PDLwSlackVerify fail")
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

func (p P2SaveData) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		From      int                 `json:"from,omitempty"`
		To        int                 `json:"to,omitempty"`
		E_x1      string              `json:"e_x1,omitempty"`
		PaiPubKey *paillier.PublicKey `json:"pai_pubkey,omitempty"`
		X2        string              `json:"x2,omitempty"`
	}{
		From:      p.From,
		To:        p.To,
		E_x1:      p.E_x1.Text(16),
		PaiPubKey: p.PaiPubKey,
		X2:        p.X2.Text(16),
	})
}

func (p *P2SaveData) UnmarshalJSON(text []byte) error {
	value := &struct {
		From      int                 `json:"from,omitempty"`
		To        int                 `json:"to,omitempty"`
		E_x1      string              `json:"e_x1,omitempty"`
		PaiPubKey *paillier.PublicKey `json:"pai_pubkey,omitempty"`
		X2        string              `json:"x2,omitempty"`
	}{}
	if err := json.Unmarshal(text, &value); err != nil {
		return fmt.Errorf("P2SaveData unmarshal error: %v", err)
	}

	var ok bool
	if p.E_x1, ok = new(big.Int).SetString(value.E_x1, 16); !ok {
		return fmt.Errorf("cannot unmarshal %q into a *big.Int", text)
	}
	if p.X2, ok = new(big.Int).SetString(value.X2, 16); !ok {
		return fmt.Errorf("cannot unmarshal %q into a *big.Int", text)
	}
	p.From = value.From
	p.To = value.To
	p.PaiPubKey = value.PaiPubKey
	return nil
}
