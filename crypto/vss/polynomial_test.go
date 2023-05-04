package vss

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
)

func TestPoly(t *testing.T) {
	ec := secp256k1.S256()

	secret := big.NewInt(int64(1))
	polynomial := InitPolynomial(ec, secret, 5)
	fmt.Println(polynomial.Coefficients)

	x := big.NewInt(int64(1))
	result := polynomial.EvaluatePolynomial(x)
	fmt.Println(result)
}

func TestLagrangian(t *testing.T) {
	ec := secp256k1.S256()
	degree := 5
	secret := big.NewInt(int64(123456))
	polynomial := InitPolynomial(ec, secret, degree)
	fmt.Println(polynomial.Coefficients)

	pointList := make([]*Share, degree+1)
	for i := 0; i < degree+1; i++ {
		x := big.NewInt(int64(10 + i))
		pointList[i] = polynomial.EvaluatePolynomial(x)
	}
	recoverSecret := RecoverSecret(ec, pointList)
	fmt.Println(recoverSecret)
}

func TestFeldman(t *testing.T) {
	curve := secp256k1.S256()
	secret := big.NewInt(int64(123456))

	feldman, _ := NewFeldman(2, 3, curve)
	verifiers, shares, _ := feldman.Evaluate(secret)

	verify, _ := feldman.Verify(shares[0], verifiers)
	fmt.Println(verify)
	verify, _ = feldman.Verify(shares[1], verifiers)
	fmt.Println(verify)
	verify, _ = feldman.Verify(shares[2], verifiers)
	fmt.Println(verify)

	w21 := CalLagrangian(curve, big.NewInt(int64(1)), shares[0].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(3))})
	w23 := CalLagrangian(curve, big.NewInt(int64(3)), shares[2].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(3))})
	fmt.Println(new(big.Int).Mod(new(big.Int).Add(w21, w23), curve.N))
}
