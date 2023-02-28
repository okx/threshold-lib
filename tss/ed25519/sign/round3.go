package sign

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
	"math/big"
)

// SignStep3  calculate R, si = ri + h * xi
func (ed25519 *Ed25519Sign) SignStep3(msgs []*tss.Message) (*big.Int, *big.Int, error) {
	if ed25519.RoundNumber != 3 {
		return nil, nil, fmt.Errorf("round error")
	}
	if len(msgs) != (ed25519.Threshold - 1) {
		return nil, nil, fmt.Errorf("messages number error")
	}
	// R = sum(Ri)
	R := curves.ScalarToPoint(curve, ed25519.ki)
	for _, msg := range msgs {
		if msg.To != ed25519.DeviceNumber {
			return nil, nil, fmt.Errorf("message sending error")
		}
		var data Step2Data
		err := json.Unmarshal([]byte(msg.Data), &data)
		if err != nil {
			return nil, nil, err
		}
		// check Ri commitment
		commit := commitment.HashCommitment{}
		commit.C = ed25519.CommitmentMap[msg.From]
		commit.Msg = data.Witness
		ok, DeC := commit.Open()
		if !ok {
			return nil, nil, fmt.Errorf("commitment DeCommit fail")
		}
		Rj, err := curves.NewECPoint(curve, DeC[0], DeC[1])
		if err != nil {
			return nil, nil, err
		}
		// ki schnorr verify, Rj = kj*G
		verify := schnorr.Verify(data.Proof, Rj)
		if !verify {
			return nil, nil, fmt.Errorf("schnorr verify fail")
		}
		R, err = R.Add(Rj)
		if err != nil {
			return nil, nil, err
		}
	}
	RR := edwards.NewPublicKey(R.X, R.Y)

	bytes, err := hex.DecodeString(ed25519.message)
	if err != nil {
		return nil, nil, err
	}
	// h = hash512(R || Pub || M)
	h := sha512.New()
	h.Reset()
	h.Write(RR.Serialize())
	h.Write(ed25519.PublicKey.Serialize())
	h.Write(bytes)

	var lambda [64]byte
	h.Sum(lambda[:0])
	var lambdaReduced [32]byte
	edwards25519.ScReduce(&lambdaReduced, &lambda)

	xBytes := bigIntToEncodedBytes(ed25519.wi)
	rBytes := bigIntToEncodedBytes(ed25519.ki)

	// si = ri + h * xi
	var sBytes [32]byte
	edwards25519.ScMulAdd(&sBytes, &lambdaReduced, xBytes, rBytes)
	si := encodedBytesToBigInt(&sBytes)
	var RBytes = copyBytes(RR.Serialize())
	r := encodedBytesToBigInt(RBytes)

	return si, r, nil
}
