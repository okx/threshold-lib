package dkg

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
)

// DKGStep3 receive second step message and execute dkg finish
// return key share information
func (info *SetupInfo) DKGStep3(msgs []*tss.Message) (*tss.KeyStep3Data, error) {
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
	chaincode := info.chaincode
	xi := info.secretShares[info.DeviceNumber-1]
	for _, msg := range msgs {
		if msg.To != info.DeviceNumber {
			return nil, fmt.Errorf("message sending error")
		}
		var data tss.KeyStep2Data
		err := json.Unmarshal([]byte(msg.Data), &data)
		if err != nil {
			return nil, err
		}
		// check verifiers commitment
		hashCommit := commitment.HashCommitment{}
		hashCommit.C = info.commitmentMap[msg.From]
		hashCommit.Msg = *data.Witness
		ok, D := hashCommit.Open()
		if !ok {
			return nil, fmt.Errorf("commitment DeCommit fail")
		}
		//  actual chaincode = sum(chaincode)
		chaincode = new(big.Int).Add(chaincode, D[0])
		verifiers[msg.From], err = UnmarshalVerifiers(curve, D[1:], info.Threshold)
		if err != nil {
			return nil, err
		}

		// feldman verify
		if ok, err := feldman.Verify(data.Share, verifiers[msg.From]); !ok {
			if err != nil {
				return nil, err
			} else {
				return nil, fmt.Errorf("invalid share for participant  ")
			}
		}
		xi.Y = new(big.Int).Add(xi.Y, data.Share.Y)

		ujPoint := verifiers[msg.From][0]
		point, err := curves.NewECPoint(curve, ujPoint.X, ujPoint.Y)
		if err != nil {
			return nil, err
		}
		// schnorr verify for ui
		verify := schnorr.Verify(data.Proof, point)
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
			if err != nil {
				return nil, err
			}
		}
		sharePubKeyMap[k] = Yi
	}
	// check share publicKey
	xiG := curves.ScalarToPoint(curve, xi.Y)
	if !sharePubKeyMap[info.DeviceNumber].Equals(xiG) {
		return nil, fmt.Errorf("public key calculation error")
	}
	info.shareI = xi.Y
	info.publicKey = v[0]

	content := &tss.KeyStep3Data{
		Id:             info.DeviceNumber,
		ShareI:         info.shareI,
		PublicKey:      info.publicKey,
		ChainCode:      hex.EncodeToString(chaincode.Bytes()),
		SharePubKeyMap: sharePubKeyMap,
	}
	return content, nil
}

func UnmarshalVerifiers(curve elliptic.Curve, msg []*big.Int, threshold int) ([]*curves.ECPoint, error) {
	if len(msg) != (threshold * 2) {
		return nil, fmt.Errorf("invalid number of verifier shares")
	}
	verifiers := make([]*curves.ECPoint, threshold)
	for k := 0; k < threshold; k++ {
		verifiers[k] = &curves.ECPoint{
			Curve: curve,
			X:     msg[2*k],
			Y:     msg[2*k+1],
		}
	}
	return verifiers, nil
}
