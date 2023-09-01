package reshare

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/key/dkg"
)

// DKGStep3 return new key share information except chaincode
func (info *RefreshInfo) DKGStep3(msgs []*tss.Message) (*tss.KeyStep3Data, error) {
	if info.RoundNumber != 3 {
		return nil, fmt.Errorf("round error")
	}
	if len(msgs) != (info.Total - 1) {
		return nil, fmt.Errorf("messages number error")
	}

	curve := info.curve
	feldman, err := vss.NewFeldman(info.Threshold, info.Total, curve)
	if err != nil {
		return nil, err
	}

	verifiers := make(map[int][]*curves.ECPoint, len(msgs))
	verifiers[info.DeviceNumber] = info.verifiers
	xi := info.secretShares[info.DeviceNumber-1]
	for _, msg := range msgs {
		if msg.To != info.DeviceNumber {
			return nil, fmt.Errorf("message sending error")
		}
		var content tss.KeyStep2Data
		err := json.Unmarshal([]byte(msg.Data), &content)
		if err != nil {
			return nil, err
		}
		hashCommit := commitment.HashCommitment{}
		hashCommit.C = info.commitmentMap[msg.From]
		hashCommit.Msg = *content.Witness
		ok, D := hashCommit.Open()
		if !ok {
			return nil, fmt.Errorf("commitment DeCommit fail")
		}

		verifiers[msg.From], err = dkg.UnmarshalVerifiers(curve, D, info.Threshold)
		if ok, err := feldman.Verify(content.Share, verifiers[msg.From]); !ok {
			if err != nil {
				return nil, err
			} else {
				return nil, fmt.Errorf("invalid share for participant  ")
			}
		}
		xi.Y = new(big.Int).Add(xi.Y, content.Share.Y)

		ujPoint := verifiers[msg.From][0]
		point, err := curves.NewECPoint(curve, ujPoint.X, ujPoint.Y)
		if err != nil {
			return nil, err
		}
		verify := schnorr.Verify(content.Proof, point)
		if !verify {
			return nil, fmt.Errorf("schnorr verify fail")
		}
	}

	v := make([]*curves.ECPoint, info.Threshold)
	for j := 0; j < info.Threshold; j++ {
		v[j] = curves.ScalarToPoint(curve, big.NewInt(0))

		for _, verifier := range verifiers {
			v[j], err = v[j].Add(verifier[j])
			if err != nil {
				return nil, err
			}
		}
	}

	sharePubKeyMap := make(map[int]*curves.ECPoint, info.Threshold)
	for k := 1; k <= info.Total; k++ {
		Yi := v[0]
		tmp := big.NewInt(1)
		for i := 1; i < info.Threshold; i++ {
			tmp = tmp.Mul(tmp, big.NewInt(int64(k)))
			point := v[i]
			point = point.ScalarMult(tmp)
			Yi, err = Yi.Add(point)
		}
		sharePubKeyMap[k] = Yi
	}
	xiG := curves.ScalarToPoint(curve, xi.Y)
	if !sharePubKeyMap[info.DeviceNumber].Equals(xiG) {
		return nil, fmt.Errorf("public key calculation error")
	}
	// update publicKey is equals previous publicKey?
	if !v[0].Equals(info.publicKey) {
		return nil, fmt.Errorf("public key recalculation error")
	}

	info.shareI = xi.Y
	info.publicKey = v[0]

	content := &tss.KeyStep3Data{
		Id:             info.DeviceNumber,
		ShareI:         info.shareI,
		PublicKey:      info.publicKey,
		SharePubKeyMap: sharePubKeyMap,
	}
	return content, nil
}
