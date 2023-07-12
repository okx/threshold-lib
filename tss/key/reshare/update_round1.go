package reshare

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
)

// DKGStep1
func (info *RefreshInfo) DKGStep1() (map[int]*tss.Message, error) {
	if info.RoundNumber != 1 {
		return nil, fmt.Errorf("round error")
	}
	feldman, err := vss.NewFeldman(info.Threshold, info.Total, info.curve)
	if err != nil {
		return nil, err
	}
	// ui calculated from previous share
	verifiers, shares, err := feldman.Evaluate(info.ui)
	if err != nil {
		return nil, err
	}

	// compute verifiers commitment， no chaincode
	var input []*big.Int
	for i := 0; i < len(verifiers); i++ {
		input = append(input, verifiers[i].X, verifiers[i].Y)
	}
	hashCommitment := commitment.NewCommitment(input...)

	info.deC = &hashCommitment.Msg
	info.secretShares = shares
	info.verifiers = verifiers
	info.RoundNumber = 2

	out := make(map[int]*tss.Message, info.Total-1)
	for _, id := range info.Ids() {
		if id == info.DeviceNumber {
			continue
		}
		content := tss.KeyStep1Data{C: &hashCommitment.C}
		bytes, err := json.Marshal(content)
		if err != nil {
			return nil, err
		}
		message := &tss.Message{
			From: info.DeviceNumber,
			To:   id,
			Data: string(bytes),
		}
		out[id] = message
	}
	return out, nil
}
