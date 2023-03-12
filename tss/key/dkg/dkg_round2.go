package dkg

import (
	"encoding/json"
	"fmt"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
)

// DKGStep2 receive first step message and execute second step
func (info *SetupInfo) DKGStep2(msgs []*tss.Message) (map[int]*tss.Message, error) {
	if info.RoundNumber != 2 {
		return nil, fmt.Errorf("round error")
	}
	if len(msgs) != (info.Total - 1) {
		return nil, fmt.Errorf("messages number error")
	}
	info.commitmentMap = make(map[int]commitment.Commitment, len(msgs))
	for _, msg := range msgs {
		if msg.To != info.DeviceNumber {
			return nil, fmt.Errorf("message sending error")
		}
		var content tss.KeyStep1Data
		err := json.Unmarshal([]byte(msg.Data), &content)
		if err != nil {
			return nil, err
		}
		info.commitmentMap[msg.From] = *content.C
	}

	// compute zkSchnorr prove for ui
	uiG := curves.ScalarToPoint(info.curve, info.ui)
	proof, err := schnorr.Prove(info.ui, uiG)
	if err != nil {
		return nil, err
	}
	info.RoundNumber = 3

	out := make(map[int]*tss.Message, info.Total-1)
	for _, id := range info.Ids() {
		if id == info.DeviceNumber {
			continue
		}
		// step2: commitment data、secretShares and schnorr proof for ui
		content := tss.KeyStep2Data{
			Witness: info.deC,
			Share:   info.secretShares[id-1],
			Proof:   proof,
		}
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
