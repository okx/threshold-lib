package dkg

import (
	"crypto/elliptic"
	"fmt"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/vss"

	"math/big"
)

type SetupInfo struct {
	DeviceNumber int // device id， start 1
	Threshold    int //  2/n, fixed 2
	Total        int // number of participants
	RoundNumber  int

	ui        *big.Int
	shareI    *big.Int // key share
	publicKey *curves.ECPoint
	curve     elliptic.Curve
	chaincode *big.Int // for non-hardened derivation, unchangeable

	verifiers     []*curves.ECPoint
	secretShares  []*vss.Share
	deC           *commitment.Witness
	commitmentMap map[int]commitment.Commitment
}

func NewSetUp(deviceNumber, total int, curve elliptic.Curve) *SetupInfo {
	if total < 2 || deviceNumber > total {
		panic(fmt.Errorf("total less than 2, or deviceNumber more than total"))
	}
	info := &SetupInfo{
		DeviceNumber: deviceNumber,
		Threshold:    2,
		Total:        total,
		RoundNumber:  1,
		curve:        curve,
	}
	return info
}
