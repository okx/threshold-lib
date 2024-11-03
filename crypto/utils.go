package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
)

var (
	one = big.NewInt(1)
)

// SHA512Int hmac sha512 []*big.Int
func SHA512Int(in ...*big.Int) *big.Int {
	hash := hmac.New(sha512.New, nil)
	for _, n := range in {
		hash.Write(n.Bytes())
	}
	bytes := hash.Sum(nil)
	return new(big.Int).SetBytes(bytes)
}

// SHA256Int sha256 []*big.Int
func SHA256Int(in ...*big.Int) *big.Int {
	hash := sha256.New()
	for _, n := range in {
		hash.Write(n.Bytes())
	}
	bytes := hash.Sum(nil)
	return new(big.Int).SetBytes(bytes)
}

// RandomNum generates a random number r, 1 < r < n.
// Input n has to be greater than 1, otherwise panic
func RandomNum(n *big.Int) *big.Int {
	if n == nil {
		panic(fmt.Errorf("RandomNum error, n is nil"))
	}
	if n.Cmp(one) != 1 {
		panic(fmt.Errorf("RandomNum error: max has to be greater than 1"))
	}
	for {
		r, err := rand.Int(rand.Reader, n)
		if err != nil {
			panic(fmt.Errorf("RandomNum error"))
		}
		if r.Cmp(one) == 1 {
			return r
		}
	}
}

// RandomPrimeNum  `r < n` and `gcd(r,n) = 1`
func RandomPrimeNum(n *big.Int) (*big.Int, error) {
	if n.Cmp(one) != 1 {
		return nil, fmt.Errorf("RandomPrimeNum error: max has to be greater than 1")
	}
	gcd := new(big.Int)
	r := new(big.Int)
	var err error
	for gcd.Cmp(one) != 0 {
		r, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		gcd = new(big.Int).GCD(nil, nil, r, n)
	}
	return r, nil
}

// GenerateSafePrime generates a prime number `p`; a prime 'p' such that 2p+1 is also prime.
func GenerateSafePrime(bits int, values chan *big.Int, quit chan int) (p *big.Int, err error) {
	for {
		select {
		case <-quit:
			return
		default:
			// this is to make it non-blocking
		}
		p, err = rand.Prime(rand.Reader, bits-1)
		if err != nil {
			return nil, err
		}
		// 2p+1
		p = new(big.Int).Lsh(p, 1)
		p = new(big.Int).Add(p, one)
		if p.ProbablyPrime(20) {
			select {
			case <-quit:
				return
			default:
				// this is to make it non-blocking
			}
			values <- p
			return
		}
	}
}

var zero = new(big.Int).SetInt64(0)

func IsInInterval(b *big.Int, bound *big.Int) bool {
	return b.Cmp(bound) == -1 && b.Cmp(zero) >= 0
}
