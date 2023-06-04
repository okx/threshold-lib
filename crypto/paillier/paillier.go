package paillier

import (
	"fmt"
	"github.com/okx/threshold-lib/crypto"
	"math/big"
	"runtime"
)

const (
	PrimeBits = 2048
)

type (
	PublicKey struct {
		N *big.Int // g = n+1, n2 = n*n
	}

	PrivateKey struct {
		PublicKey
		Lambda *big.Int // lcm(p-1, q-1)
		Phi    *big.Int // (p-1) * (q-1)
	}
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

// NewKeyPair generate paillier key pair
func NewKeyPair(concurrency ...int) (*PrivateKey, *PublicKey, error) {
	var currency int
	if 0 < len(concurrency) {
		currency = concurrency[0]
	} else {
		currency = runtime.NumCPU()
	}

	var values = make(chan *big.Int)
	var quit = make(chan int)
	var p, q *big.Int
	for p == q {
		for i := 0; i < currency; i++ {
			go crypto.GenerateSafePrime(PrimeBits/2, values, quit)
		}
		p, q = <-values, <-values
		close(quit)
	}

	// n = p*q
	n := new(big.Int).Mul(p, q)

	// phi = (p-1) * (q-1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	// lambda = lcm(p−1, q−1)
	gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
	lambda := new(big.Int).Div(phi, gcd)

	publicKey := &PublicKey{N: n}
	privateKey := &PrivateKey{PublicKey: *publicKey, Lambda: lambda, Phi: phi}
	return privateKey, publicKey, nil
}

// Encrypt E(m) =  (g^m) * (r^n) mod n^2
func (pk *PublicKey) Encrypt(m *big.Int) (*big.Int, *big.Int, error) {
	r, err := crypto.RandomPrimeNum(pk.N)
	if err != nil {
		return nil, nil, fmt.Errorf("getRandom error")
	}
	c, err := pk.EncryptWithR(m, r)
	if err != nil {
		return nil, nil, fmt.Errorf("EncryptRandom error")
	}
	return c, r, err
}

// EncryptWithR E(m) =  (g^m) * (r^n) mod n^2
func (pk *PublicKey) EncryptWithR(m, r *big.Int) (c *big.Int, err error) {
	if m.Cmp(zero) == -1 || m.Cmp(pk.N) != -1 { // 0 <=  m < N
		return nil, fmt.Errorf("m range error")
	}
	N2 := pk.N2()
	// g^m mod N2
	Gm := new(big.Int).Exp(pk.G(), m, N2)
	// r^n mod N2
	xN := new(big.Int).Exp(r, pk.N, N2)
	//  (g^m) * (r^n) mod N2
	c = new(big.Int).Mod(new(big.Int).Mul(Gm, xN), N2)
	return
}

// HomoMulPlain  E(ab) = E(a) ^ b mod n^2
func (pk *PublicKey) HomoMulPlain(c1, m *big.Int) (*big.Int, error) {
	if m.Cmp(zero) == -1 || m.Cmp(pk.N) != -1 { // 0 <=  m < N
		return nil, fmt.Errorf("m range error")
	}
	N2 := pk.N2()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { //  // 0 <= c1 < N2
		return nil, fmt.Errorf("c range error")
	}
	// c^m mod N2
	return new(big.Int).Exp(c1, m, N2), nil
}

// HomoAdd E(ab)=E(a)*E(b) mod n^2
func (pk *PublicKey) HomoAdd(c1, c2 *big.Int) (*big.Int, error) {
	N2 := pk.N2()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { //  // 0 <= c1 < N2
		return nil, fmt.Errorf("c1 range error")
	}
	if c2.Cmp(zero) == -1 || c2.Cmp(N2) != -1 { //  // 0 <= c2 < N2
		return nil, fmt.Errorf("c2 range error")
	}
	// c1 * c2 mod N2
	return new(big.Int).Mod(new(big.Int).Mul(c1, c2), N2), nil
}

// HomoAddPlain   E(a+b) = E(a) * g^b mod n^2
//						 = E(a) * (1 + b*n) mod n^2
func (pk *PublicKey) HomoAddPlain(eA, b *big.Int) (*big.Int, error) {
	N2 := pk.N2()
	if eA.Cmp(zero) == -1 || eA.Cmp(N2) != -1 { //  // 0 <= eA < N2
		return nil, fmt.Errorf("eA range error")
	}
	if b.Cmp(zero) == -1 || b.Cmp(pk.N) != -1 { //  // 0 <= b < N
		return nil, fmt.Errorf("c2 range error")
	}
	gb := new(big.Int).Add(new(big.Int).Mul(b, pk.N), one)
	return new(big.Int).Mod(new(big.Int).Mul(eA, gb), N2), nil
}

// n*n
func (pk *PublicKey) N2() *big.Int {
	return new(big.Int).Mul(pk.N, pk.N)
}

// g = n + 1
func (pk *PublicKey) G() *big.Int {
	return new(big.Int).Add(pk.N, one)
}

// Decrypt m = L(c^lambda mod n^2) * mu mod n
func (priv *PrivateKey) Decrypt(c *big.Int) (m *big.Int, err error) {
	N2 := priv.N2()
	if c.Cmp(zero) == -1 || c.Cmp(N2) != -1 { // 0 <= c < N2
		return nil, fmt.Errorf("c range error")
	}
	cg := new(big.Int).GCD(nil, nil, c, N2)
	if cg.Cmp(one) == 1 {
		return nil, fmt.Errorf("the message is mal-formed")
	}
	//  lc = L[(c^Lambda mod N2) / N]
	lc := l(new(big.Int).Exp(c, priv.Lambda, N2), priv.N)
	// lg = L[(g^Lambda mod N2) / N]
	lg := l(new(big.Int).Exp(priv.G(), priv.Lambda, N2), priv.N)
	// m = (lc/lg) mod N
	inv := new(big.Int).ModInverse(lg, priv.N)
	m = new(big.Int).Mod(new(big.Int).Mul(lc, inv), priv.N)
	return
}

// l(x) = (x-1)/N
func l(u, N *big.Int) *big.Int {
	t := new(big.Int).Sub(u, one)
	return new(big.Int).Div(t, N)
}
