package schnorr

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
)

type Proof struct {
	R *curves.ECPoint
	S *big.Int
}

// Prove schnorr s = r + hx
func Prove(x *big.Int, X *curves.ECPoint) (*Proof, error) {
	if x == nil || X == nil {
		return nil, fmt.Errorf("schnorr prove parameters error")
	}
	q := X.Curve.Params().N

	r := crypto.RandomNum(q)
	R := curves.ScalarToPoint(X.Curve, r)

	h := crypto.SHA256Int(X.X, X.Y, R.X, R.Y)
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
	if !pf.R.IsOnCurve() {
		return false
	}
	q := X.Curve.Params().N
	h := crypto.SHA256Int(X.X, X.Y, pf.R.X, pf.R.Y)
	h = new(big.Int).Mod(h, q)

	SG := curves.ScalarToPoint(X.Curve, pf.S)
	Xh := X.ScalarMult(h)
	RXh, err := pf.R.Add(Xh)
	if err != nil {
		return false
	}
	return RXh.X.Cmp(SG.X) == 0 && RXh.Y.Cmp(SG.Y) == 0
}

func (p Proof) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		R *curves.ECPoint `json:"r,omitempty"`
		S string          `json:"s,omitempty"`
	}{
		R: p.R,
		S: p.S.Text(16),
	})
}

func (p *Proof) UnmarshalJSON(text []byte) error {
	value := &struct {
		R *curves.ECPoint `json:"r,omitempty"`
		S string          `json:"s,omitempty"`
	}{}
	if err := json.Unmarshal(text, &value); err != nil {
		return fmt.Errorf("SchnorrProof unmarshal error: %v", err)
	}

	p.R = value.R
	var ok bool
	if p.S, ok = new(big.Int).SetString(value.S, 16); !ok {
		return fmt.Errorf("cannot unmarshal %q into a *big.Int", text)
	}
	return nil
}
