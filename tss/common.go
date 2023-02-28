package tss

import (
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
	"math/big"
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
