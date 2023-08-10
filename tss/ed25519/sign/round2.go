package sign

import (
	"encoding/json"
	"fmt"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
)

type Step2Data struct {
	Witness commitment.Witness
	Proof   *schnorr.Proof
}

// SignStep2
func (ed25519 *Ed25519Sign) SignStep2(msgs []*tss.Message) (map[int]*tss.Message, error) {
	if ed25519.RoundNumber != 2 {
		return nil, fmt.Errorf("round error")
	}
	if len(msgs) != (ed25519.Threshold - 1) {
		return nil, fmt.Errorf("messages number error")
	}
	// received step1 message from others
	ed25519.CommitmentMap = make(map[int]commitment.Commitment, len(msgs))
	for _, msg := range msgs {
		if msg.To != ed25519.DeviceNumber {
			return nil, fmt.Errorf("message sending error")
		}
		var content Step1Data
		err := json.Unmarshal([]byte(msg.Data), &content)
		if err != nil {
			return nil, err
		}
		ed25519.CommitmentMap[msg.From] = content.C
	}
	// zk schnorr prove ki
	uiG := curves.ScalarToPoint(curve, ed25519.ki)
	proof, err := schnorr.Prove(ed25519.ki, uiG)
	if err != nil {
		return nil, err
	}
	ed25519.RoundNumber = 3

	out := make(map[int]*tss.Message, ed25519.Threshold-1)
	for _, i := range ed25519.partList {
		if i == ed25519.DeviceNumber {
			continue
		}
		data := Step2Data{
			Witness: ed25519.cmtD,
			Proof:   proof,
		}
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

func (s Step2Data) MarshalJSON() ([]byte, error) {
	wits := commitment.WitnessMarshalJSON(s.Witness)
	return json.Marshal(&struct {
		Witness []string       `json:"witness,omitempty"`
		Proof   *schnorr.Proof `json:"proof,omitempty"`
	}{
		Witness: wits,
		Proof:   s.Proof,
	})
}

func (s *Step2Data) UnmarshalJSON(text []byte) error {
	value := &struct {
		Witness []string       `json:"witness,omitempty"`
		Proof   *schnorr.Proof `json:"proof,omitempty"`
	}{}
	if err := json.Unmarshal(text, &value); err != nil {
		return fmt.Errorf("Step1Data unmarshal error: %v", err)
	}

	witness, err := commitment.WitnessUnmarshalJSON(value.Witness)
	if err != nil {
		return err
	}
	s.Witness = witness
	s.Proof = value.Proof
	return nil
}
