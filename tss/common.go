package tss

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
)

type Message struct {
	From int
	To   int
	Data string
}

type KeyStep1Data struct {
	C *commitment.Commitment
}

type KeyStep2Data struct {
	Witness *commitment.Witness
	Share   *vss.Share // secret share
	Proof   *schnorr.Proof
}

type KeyStep3Data struct {
	Id             int
	ShareI         *big.Int                // key share
	PublicKey      *curves.ECPoint         // PublicKey
	ChainCode      string                  // chaincode for derivation, no longer change when update
	SharePubKeyMap map[int]*curves.ECPoint //  ShareI*G map
}

func (k KeyStep1Data) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		C string `json:"c,omitempty"`
	}{
		C: (*k.C).Text(16),
	})
}

func (k *KeyStep1Data) UnmarshalJSON(text []byte) error {
	value := &struct {
		C string `json:"c,omitempty"`
	}{}

	if err := json.Unmarshal(text, &value); err != nil {
		return fmt.Errorf("KeyStep1Data unmarshal error: %v", err)
	}

	bigInt, ok := new(big.Int).SetString(value.C, 16)
	if !ok {
		return fmt.Errorf("cannot unmarshal %q into a *big.Int", text)
	}
	k.C = &bigInt
	return nil
}

func (k KeyStep2Data) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Witness []string       `json:"witness,omitempty"`
		Share   *vss.Share     `json:"share,omitempty"`
		Proof   *schnorr.Proof `json:"proof,omitempty"`
	}{
		Witness: commitment.WitnessMarshalJSON(*k.Witness),
		Share:   k.Share,
		Proof:   k.Proof,
	})
}

func (k *KeyStep2Data) UnmarshalJSON(text []byte) error {
	value := &struct {
		Witness []string       `json:"witness,omitempty"`
		Share   *vss.Share     `json:"share,omitempty"`
		Proof   *schnorr.Proof `json:"proof,omitempty"`
	}{}
	if err := json.Unmarshal(text, &value); err != nil {
		return fmt.Errorf("KeyStep2Data unmarshal error: %v", err)
	}

	witness, err := commitment.WitnessUnmarshalJSON(value.Witness)
	if err != nil {
		return err
	}
	k.Witness = &witness
	k.Share = value.Share
	k.Proof = value.Proof
	return nil
}

func (k KeyStep3Data) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Id             int                     `json:"id,omitempty"`
		ShareI         string                  `json:"share_i,omitempty"`
		PublicKey      *curves.ECPoint         `json:"public_key,omitempty"`
		ChainCode      string                  `json:"chaincode,omitempty"`
		SharePubKeyMap map[int]*curves.ECPoint `json:"share_pubkey_map,omitempty"`
	}{
		Id:             k.Id,
		ShareI:         k.ShareI.Text(16),
		PublicKey:      k.PublicKey,
		ChainCode:      k.ChainCode,
		SharePubKeyMap: k.SharePubKeyMap,
	})
}

func (k *KeyStep3Data) UnmarshalJSON(text []byte) error {
	value := &struct {
		Id             int                     `json:"id,omitempty"`
		ShareI         string                  `json:"share_i,omitempty"`
		PublicKey      *curves.ECPoint         `json:"public_key,omitempty"`
		ChainCode      string                  `json:"chaincode,omitempty"`
		SharePubKeyMap map[int]*curves.ECPoint `json:"share_pubkey_map,omitempty"`
	}{}
	if err := json.Unmarshal(text, &value); err != nil {
		return fmt.Errorf("KeyStep3Data unmarshal error: %v", err)
	}

	var ok bool
	if k.ShareI, ok = new(big.Int).SetString(value.ShareI, 16); !ok {
		return fmt.Errorf("cannot unmarshal %q into a *big.Int", text)
	}
	k.Id = value.Id
	k.PublicKey = value.PublicKey
	k.ChainCode = value.ChainCode
	k.SharePubKeyMap = value.SharePubKeyMap
	return nil
}
