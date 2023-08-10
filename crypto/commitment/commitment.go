package commitment

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto"
)

type (
	Commitment = *big.Int
	Witness    = []*big.Int

	HashCommitment struct {
		C   Commitment
		Msg Witness
	}
)

// NewCommitment commit []*big.int use sha512
func NewCommitment(secrets ...*big.Int) *HashCommitment {
	var rBytes [32]byte
	_, err := rand.Read(rBytes[:])
	if err != nil {
		return nil
	}
	r := new(big.Int).SetBytes(rBytes[:])
	parts := make([]*big.Int, len(secrets)+1)
	parts[0] = r
	for i := 1; i < len(parts); i++ {
		parts[i] = secrets[i-1]
	}
	hash := crypto.SHA512Int(parts...)

	cmt := &HashCommitment{}
	cmt.C = hash
	cmt.Msg = parts
	return cmt
}

// Verify verify the commitment
func (cmt *HashCommitment) Verify() bool {
	C, D := cmt.C, cmt.Msg
	if C == nil || D == nil {
		return false
	}
	hash := crypto.SHA512Int(D...)
	return hash.Cmp(C) == 0
}

// Open open the commitment
func (cmt *HashCommitment) Open() (bool, Witness) {
	if cmt.Verify() {
		return true, cmt.Msg[1:]
	} else {
		return false, nil
	}
}

func WitnessMarshalJSON(witness Witness) []string {
	var msgs []string
	for _, m := range witness {
		msgs = append(msgs, m.Text(16))
	}
	return msgs
}

func WitnessUnmarshalJSON(text []string) (Witness, error) {
	var witness []*big.Int
	for _, m := range text {
		w, b := new(big.Int).SetString(m, 16)
		if !b {
			return nil, fmt.Errorf("cannot unmarshal %q into a *big.Int", m)
		}
		witness = append(witness, w)
	}
	return witness, nil
}

func (cmt HashCommitment) MarshalJSON() ([]byte, error) {
	msgs := WitnessMarshalJSON(cmt.Msg)
	return json.Marshal(&struct {
		C   string   `json:"c,omitempty"`
		Msg []string `json:"msg,omitempty"`
	}{
		C:   cmt.C.Text(16),
		Msg: msgs,
	})
}

func (cmt *HashCommitment) UnmarshalJSON(text []byte) error {
	value := &struct {
		C   string   `json:"c,omitempty"`
		Msg []string `json:"msg,omitempty"`
	}{}
	if err := json.Unmarshal(text, &value); err != nil {
		return fmt.Errorf("HashCommitment unmarshal error: %v", err)
	}

	var ok bool
	if cmt.C, ok = new(big.Int).SetString(value.C, 16); !ok {
		return fmt.Errorf("cannot unmarshal %q into a *big.Int", text)
	}

	var err error
	cmt.Msg, err = WitnessUnmarshalJSON(value.Msg)
	if err != nil {
		return err
	}

	return nil
}
