package dkg

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
)

// DKGStep1 p2p send verifiers commitment
func (info *SetupInfo) DKGStep1() (map[int]*tss.Message, error) {
	if info.RoundNumber != 1 {
		return nil, fmt.Errorf("round error")
	}
	// random generate ui, private key = sum(ui)
	ui := crypto.RandomNum(info.curve.Params().N)
	feldman, err := vss.NewFeldman(info.Threshold, info.Total, info.curve)
	if err != nil {
		return nil, err
	}
	// verifiers [a0*G, a1*G, ...], shares [fi(1), fi(2), ...]
	verifiers, shares, err := feldman.Evaluate(ui)
	if err != nil {
		return nil, err
	}
	// each one generates a chaincode, actual chaincode = sum(chaincode)
	chaincode := crypto.RandomNum(info.curve.Params().N)

	// compute verifiers and chaincode commitment
	var input []*big.Int
	input = append(input, chaincode)
	for i := 0; i < len(verifiers); i++ {
		input = append(input, verifiers[i].X, verifiers[i].Y)
	}
	hashCommitment := commitment.NewCommitment(input...)

	info.ui = ui
	info.deC = &hashCommitment.Msg
	info.secretShares = shares
	info.verifiers = verifiers
	info.chaincode = chaincode
	info.RoundNumber = 2

	out := make(map[int]*tss.Message, info.Total-1)
	for _, id := range info.Ids() {
		if id == info.DeviceNumber {
			continue
		}
		// each message send p2p, not broadcast
		// step1: verifiers commitment
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
