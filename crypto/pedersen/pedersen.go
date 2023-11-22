package pedersen

import (
	"math/big"
	"runtime"

	"github.com/okx/threshold-lib/crypto"
)

const (
	PrimeBits = 1024
)

type (
	// N = p * q, where p and q are safe primes
	// s = rnd1^2 mod N
	// t = rnd2^2 mod N
	PedersenParameters struct {
		S, T, Ntilde *big.Int
	}
)

func NewPedersenParameters(concurrency ...int) (*PedersenParameters, error) {
	var currency int
	if 0 < len(concurrency) {
		currency = concurrency[0]
	} else {
		currency = runtime.NumCPU()
	}

	var values = make(chan *big.Int, currency)
	var p, q *big.Int
	for p == q {
		var quit = make(chan int)
		for i := 0; i < currency; i++ {
			go crypto.GenerateSafePrime(PrimeBits, values, quit)
		}
		p, q = <-values, <-values
		close(quit)
	}

	// N = p * q, as described in the paper: https://eprint.iacr.org/2020/492.pdf Definition 1.2
	N := new(big.Int).Mul(p, q)
	rnd1 := crypto.RandomNum(N)
	rnd2 := crypto.RandomNum(N)

	s := new(big.Int).Mod(new(big.Int).Mul(rnd1, rnd1), N)
	t := new(big.Int).Mod(new(big.Int).Mul(rnd2, rnd2), N)

	return &PedersenParameters{Ntilde: N, S: s, T: t}, nil
}

// commit c = s^m * t^r mod N
func (pedersen *PedersenParameters) Commit(m, r *big.Int) (*big.Int, error) {
	a := new(big.Int).Exp(pedersen.S, m, pedersen.Ntilde)
	b := new(big.Int).Exp(pedersen.T, r, pedersen.Ntilde)
	c := new(big.Int).Mod(new(big.Int).Mul(a, b), pedersen.Ntilde)
	return c, nil
}

// open c = s^m * t^r mod N
func (pedersen *PedersenParameters) Open(c, m, r *big.Int) (bool, error) {
	a := new(big.Int).Exp(pedersen.S, m, pedersen.Ntilde)
	b := new(big.Int).Exp(pedersen.T, r, pedersen.Ntilde)
	c1 := new(big.Int).Mod(new(big.Int).Mul(a, b), pedersen.Ntilde)
	return c1.Cmp(c) == 0, nil
}
