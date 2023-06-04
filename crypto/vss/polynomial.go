package vss

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

type Polynomial struct {
	Coefficients []*big.Int // polynomial coefficient, eg: [a0, a1, a2 ...]
	QMod         *big.Int
}

// secret share
type Share struct {
	Id *big.Int // x-coordinate
	Y  *big.Int // y-coordinate
}

// InitPolynomial init Coefficients [a0, a1....at] t=degree
func InitPolynomial(curve elliptic.Curve, secret *big.Int, degree int) *Polynomial {
	q := curve.Params().N
	Coefficients := make([]*big.Int, degree+1)
	Coefficients[0] = secret
	for i := 1; i <= degree; i++ {
		r, _ := rand.Prime(rand.Reader, q.BitLen())
		Coefficients[i] = r // random generation coefficient
	}
	return &Polynomial{
		Coefficients: Coefficients,
		QMod:         q,
	}
}

// EvaluatePolynomial a polynomial with coefficients such that:
// EvaluatePolynomial(x):
// 		returns a + bx + cx^2 + dx^3
func (p *Polynomial) EvaluatePolynomial(x *big.Int) *Share {
	result := new(big.Int).Set(p.Coefficients[0])
	tmp := big.NewInt(1)
	for i := 1; i <= len(p.Coefficients)-1; i++ {
		tmp = new(big.Int).Mul(tmp, x)
		aiXi := new(big.Int).Mul(p.Coefficients[i], tmp)
		result = result.Add(result, aiXi)
	}
	result = new(big.Int).Mod(result, p.QMod)
	return &Share{
		Id: x,
		Y:  result,
	}
}

// RecoverSecret recover secret key
func RecoverSecret(curve elliptic.Curve, pointList []*Share) *big.Int {
	q := curve.Params().N
	xList := make([]*big.Int, len(pointList))
	for i, point := range pointList {
		xList[i] = point.Id
	}
	secret := big.NewInt(0)
	for _, point := range pointList {
		wi := CalLagrangian(curve, point.Id, point.Y, xList)
		secret = secret.Add(secret, wi)
	}
	secret = new(big.Int).Mod(secret, q)
	return secret
}

// CalLagrangian lagrangian interpolation wi, x = sum(wi)
func CalLagrangian(curve elliptic.Curve, x, y *big.Int, xList []*big.Int) *big.Int {
	q := curve.Params().N
	wi := new(big.Int).SetBytes(y.Bytes())
	// wi = y*mul(xj/(xj-xi))
	for i := 0; i < len(xList); i++ {
		xj := xList[i]
		if x.Cmp(xj) == 0 {
			continue
		}
		coef := new(big.Int).Sub(xj, x)
		coef.ModInverse(coef, q)
		coef.Mul(xj, coef)
		wi.Mul(wi, coef)
	}
	wi = new(big.Int).Mod(wi, q)
	return wi
}
