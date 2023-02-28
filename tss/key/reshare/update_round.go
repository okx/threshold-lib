package reshare

import (
	"crypto/elliptic"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/vss"
	"math/big"
)

type RefreshInfo struct {
	DeviceNumber int
	Threshold    int // 2/n
	Total        int
	RoundNumber  int

	curve      elliptic.Curve
	devoteList [2]int // 2 contributors reset the key share
	isDevotee  bool   // contributors and non-contributors count differently
	ui         *big.Int
	shareI     *big.Int
	publicKey  *curves.ECPoint

	verifiers     []*curves.ECPoint
	secretShares  []*vss.Share
	deC           *commitment.Witness
	commitmentMap map[int]commitment.Commitment
}

// NewRefresh the process is consistent with dkg
func NewRefresh(deviceNumber, total int, devoteList [2]int, ShareI *big.Int, PublicKey *curves.ECPoint) *RefreshInfo {
	curve := PublicKey.Curve
	info := &RefreshInfo{
		DeviceNumber: deviceNumber,
		Threshold:    2,
		Total:        total,
		RoundNumber:  1,
		devoteList:   devoteList,
		publicKey:    PublicKey,
		curve:        curve,
	}

	if deviceNumber == devoteList[0] || deviceNumber == devoteList[1] {
		info.isDevotee = true
		ints := []*big.Int{big.NewInt(int64(devoteList[0])), big.NewInt(int64(devoteList[1]))}
		info.ui = vss.CalLagrangian(curve, big.NewInt(int64(deviceNumber)), ShareI, ints)
	} else {
		// Useless, consistent with dkg
		info.ui = crypto.RandomNum(curve.Params().N)
		info.isDevotee = false
	}
	return info
}
