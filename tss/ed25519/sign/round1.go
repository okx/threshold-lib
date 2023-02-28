package sign

import (
	"encoding/json"
	"fmt"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/tss"
)

type Step1Data struct {
	C commitment.Commitment
}

// SignStep1 p2p send Ri commitment
func (ed25519 *Ed25519Sign) SignStep1() (map[int]*tss.Message, error) {
	if ed25519.RoundNumber != 1 {
		return nil, fmt.Errorf("round error")
	}
	ed25519.ki = crypto.RandomNum(curve.N)
	Ri := curves.ScalarToPoint(curve, ed25519.ki)
	// Ri commitment
	cmt := commitment.NewCommitment(Ri.X, Ri.Y)
	ed25519.cmtD = cmt.Msg
	ed25519.RoundNumber = 2

	out := make(map[int]*tss.Message, ed25519.Threshold-1)
	for _, i := range ed25519.partList {
		if i == ed25519.DeviceNumber {
			continue
		}
		// p2p send message
		data := Step1Data{C: cmt.C}
		bytes, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		message := &tss.Message{
			From: ed25519.DeviceNumber,
			To:   i,
			Data: string(bytes),
		}
		out[i] = message
	}
	return out, nil
}
