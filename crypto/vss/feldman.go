package vss

import (
	"crypto/elliptic"
	"fmt"
	"github.com/okx/threshold-lib/crypto/curves"
	"math/big"
)

//  verifiable secret sharing scheme
type Feldman struct {
	threshold int // power of polynomial add one
	limit     int //
	curve     elliptic.Curve
}

// NewFeldman
func NewFeldman(threshold, limit int, curve elliptic.Curve) (*Feldman, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("threshold least than 2")
	}
	if limit < threshold {
		return nil, fmt.Errorf("NewFeldman error, limit less than threshold")
	}
	return &Feldman{threshold, limit, curve}, nil
}

// Evaluate return verifiers and shares
func (fm *Feldman) Evaluate(secret *big.Int) ([]*curves.ECPoint, []*Share, error) {
	poly := InitPolynomial(fm.curve, secret, fm.threshold-1)
	shares := make([]*Share, fm.limit)
	for i := 1; i <= fm.limit; i++ {
		shares[i-1] = poly.EvaluatePolynomial(big.NewInt(int64(i)))
	}
	verifiers := make([]*curves.ECPoint, len(poly.Coefficients))
	for i, c := range poly.Coefficients {
		verifiers[i] = curves.ScalarToPoint(fm.curve, c)
	}
	return verifiers, shares, nil
}

// Verify check feldman verifiable secret sharing
func (fm *Feldman) Verify(share *Share, verifiers []*curves.ECPoint) (bool, error) {
	if len(verifiers) < fm.threshold {
		return false, fmt.Errorf("feldman verify number error")
	}
	lhs := curves.ScalarToPoint(fm.curve, share.Y)

	var err error
	x := big.NewInt(1)
	rhs := verifiers[0]
	for j := 1; j < len(verifiers); j++ {
		x = new(big.Int).Mul(x, share.Id)
		c := verifiers[j].ScalarMult(x)
		rhs, err = rhs.Add(c)
		if err != nil {
			return false, err
		}
	}
	return lhs.Equals(rhs), nil
}
