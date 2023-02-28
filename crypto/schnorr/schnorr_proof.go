package schnorr

import (
	"errors"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"math/big"
)

type Proof struct {
	R *curves.ECPoint
	S *big.Int
}

// Prove schnorr s = r + hx
func Prove(x *big.Int, X *curves.ECPoint) (*Proof, error) {
	if x == nil || X == nil {
		return nil, errors.New("schnorr proves parameters error")
	}
	q := X.Curve.Params().N

	r := crypto.RandomNum(q)
	R := curves.ScalarToPoint(X.Curve, r)

	h := crypto.SHA512Int(X.X, X.Y, R.X, R.Y)
	h = new(big.Int).Mod(h, q)

	s := new(big.Int).Mul(h, x)
	s = new(big.Int).Mod(new(big.Int).Add(r, s), q)
	return &Proof{R: R, S: s}, nil
}

// Verify s*G = R + h*X
func Verify(pf *Proof, X *curves.ECPoint) bool {
	if pf == nil || pf.R == nil || pf.S == nil {
		return false
	}
	q := X.Curve.Params().N
	h := crypto.SHA512Int(X.X, X.Y, pf.R.X, pf.R.Y)
	h = new(big.Int).Mod(h, q)

	SG := curves.ScalarToPoint(X.Curve, pf.S)
	Xh := X.ScalarMult(h)
	RXh, err := pf.R.Add(Xh)
	if err != nil {
		return false
	}
	return RXh.X.Cmp(SG.X) == 0 && RXh.Y.Cmp(SG.Y) == 0
}
