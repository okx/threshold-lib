package sign

import (
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/vss"
	"math/big"
)

var (
	curve = edwards.Edwards()
)

type Ed25519Sign struct {
	DeviceNumber int
	Threshold    int
	partList     []int // participating signature number, usually 2
	wi           *big.Int
	PublicKey    *edwards.PublicKey
	RoundNumber  int
	ki           *big.Int
	message      string

	cmtD          commitment.Witness
	CommitmentMap map[int]commitment.Commitment
}

// NewEd25519Sign
func NewEd25519Sign(deviceNumber, threshold int, partList []int, ShareI *big.Int, PublicKey *edwards.PublicKey, message string) *Ed25519Sign {
	if len(partList) != threshold {
		return nil
	}
	xList := make([]*big.Int, len(partList))
	for i, x := range partList {
		xList[i] = big.NewInt(int64(x))
	}
	// lagrangian interpolation wi
	wi := vss.CalLagrangian(curve, big.NewInt(int64(deviceNumber)), ShareI, xList)

	ed25519 := &Ed25519Sign{
		DeviceNumber: deviceNumber,
		Threshold:    threshold,
		wi:           wi,
		partList:     partList,
		PublicKey:    PublicKey,
		message:      message,
		RoundNumber:  1,
	}
	return ed25519
}
