package curves

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

type ECPoint struct {
	Curve elliptic.Curve
	X     *big.Int
	Y     *big.Int
}

// ScalarToPoint return public key k*G
func ScalarToPoint(curve elliptic.Curve, k *big.Int) *ECPoint {
	k = new(big.Int).Mod(k, curve.Params().N)

	point := new(ECPoint)
	point.Curve = curve
	point.X, point.Y = curve.ScalarBaseMult(k.Bytes())
	return point
}

func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
	if !curve.IsOnCurve(X, Y) {
		return nil, fmt.Errorf("NewECPoint error")
	}
	return &ECPoint{curve, X, Y}, nil
}

// Add two point add
func (p *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	x, y := p.Curve.Add(p.X, p.Y, p1.X, p1.Y)
	return NewECPoint(p.Curve, x, y)
}

func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	x, y := p.Curve.ScalarMult(p.X, p.Y, k.Bytes())
	newP, _ := NewECPoint(p.Curve, x, y)
	return newP
}

func (p *ECPoint) Equals(p2 *ECPoint) bool {
	if p == nil || p2 == nil {
		return false
	}
	return p.X.Cmp(p2.X) == 0 && p.Y.Cmp(p2.Y) == 0
}

func (p *ECPoint) SetCurve(curve elliptic.Curve) *ECPoint {
	p.Curve = curve
	return p
}

func (p *ECPoint) IsOnCurve() bool {
	return p.Curve.IsOnCurve(p.X, p.Y)
}

func (p *ECPoint) MarshalJSON() ([]byte, error) {
	curveName := GetCurveName(p.Curve)
	if len(curveName) == 0 {
		return nil, fmt.Errorf("MarshalJSON error, curves are not supported")
	}

	return json.Marshal(&struct {
		Curve string
		X     *big.Int
		Y     *big.Int
	}{
		Curve: curveName,
		X:     p.X,
		Y:     p.Y,
	})
}

func (p *ECPoint) UnmarshalJSON(payload []byte) error {
	aux := &struct {
		Curve string
		X     *big.Int
		Y     *big.Int
	}{}
	if err := json.Unmarshal(payload, &aux); err != nil {
		return err
	}
	p.X = aux.X
	p.Y = aux.Y
	p.Curve = GetCurveByName(aux.Curve)

	if !p.IsOnCurve() {
		return fmt.Errorf("UnmarshalJSON error, point not on the curves ")
	}
	return nil
}

func (p *ECPoint) PointToEcdsaPubKey() string {
	publicKey := btcec.PublicKey{Curve: p.Curve, X: p.X, Y: p.Y}
	return hex.EncodeToString(publicKey.SerializeCompressed())
}

func (p *ECPoint) PointToEd25519PubKey() string {
	publicKey := edwards.PublicKey{Curve: p.Curve, X: p.X, Y: p.Y}
	return hex.EncodeToString(publicKey.SerializeCompressed())
}

func EcdsaPubKeyToPoint(pubkeyStr string) (*ECPoint, error) {
	pubKeyBytes, err := hex.DecodeString(pubkeyStr)
	if err != nil {
		return &ECPoint{}, err
	}
	publicKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		return &ECPoint{}, err
	}
	return &ECPoint{
		X:     publicKey.X,
		Y:     publicKey.Y,
		Curve: publicKey.Curve,
	}, nil
}

func Ed25519PubKeyToPoint(pubkeyStr string) (*ECPoint, error) {
	pubKeyBytes, err := hex.DecodeString(pubkeyStr)
	if err != nil {
		return &ECPoint{}, err
	}
	publicKey, err := edwards.ParsePubKey(pubKeyBytes)
	if err != nil {
		return &ECPoint{}, err
	}
	return &ECPoint{
		X:     publicKey.X,
		Y:     publicKey.Y,
		Curve: publicKey.Curve,
	}, nil
}
