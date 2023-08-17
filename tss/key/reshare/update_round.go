package reshare

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/vss"
)

type RefreshInfo struct {
	DeviceNumber int
	Threshold    int // 2/n
	Total        int
	RoundNumber  int

	curve      elliptic.Curve
	devoteList [2]int // 2 contributors reset the key share
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
	if total < 2 || deviceNumber > total || deviceNumber <= 0 {
		panic(fmt.Errorf("NewRefresh params error"))
	}
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
		ints := []*big.Int{big.NewInt(int64(devoteList[0])), big.NewInt(int64(devoteList[1]))}
		info.ui = vss.CalLagrangian(curve, big.NewInt(int64(deviceNumber)), ShareI, ints)
	} else {
		info.ui = big.NewInt(0)
	}
	return info
}

func (info *RefreshInfo) Ids() []int {
	var ids []int
	for i := 1; i <= info.Total; i++ {
		ids = append(ids, i)
	}
	return ids
}
