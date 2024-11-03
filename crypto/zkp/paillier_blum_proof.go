package zkp

import (
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto"
)

type (
	PaillierBlumProof struct {
		W            *big.Int
		X_arr, Z_arr []*big.Int
		A            *big.Int // the i-th bit sets the a value at iteration i
		B            *big.Int // the i-th bit sets the b value at iteration j
		M            int      // the number of iteration, soundness error probability 2^-m
	}
)

const kMinSampleCount = 40

// https://eprint.iacr.org/2020/492.pdf 4.3 Paillier Blum Modulus ZK
func PaillierBlumProve(N, p, q *big.Int) (*PaillierBlumProof, error) {
	m := 64
	if N.Cmp(new(big.Int).Mul(p, q)) != 0 {
		return nil, fmt.Errorf("the N [%d] is not the product of p [%d] and q [%d]. ", N, p, q)
	}

	w := crypto.RandomNum(N)
	for big.Jacobi(w, N) != -1 {
		w = crypto.RandomNum(N)
	}

	y_arr := make([]*big.Int, m)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	N_Inv := new(big.Int).ModInverse(N, phi)

	X_arr := make([]*big.Int, m)
	Z_arr := make([]*big.Int, m)
	// Fix bitLen of A and B to m+1
	A := new(big.Int).Lsh(one, uint(m))
	B := new(big.Int).Lsh(one, uint(m))

	var err error
	for i := 0; i < m; i++ {
		// can concurrently prove using goroutines
		e := oracle(w, N, y_arr[0:i])
		y_arr[i] = new(big.Int).Mod(e, N)
		var a, b bool
		X_arr[i], a, b, err = getQuarticRoot(N, phi, p, q, w, y_arr[i])
		if a {
			A.SetBit(A, i, 1)
		} else {
			A.SetBit(A, i, 0)
		}
		if b {
			B.SetBit(B, i, 1)
		} else {
			B.SetBit(B, i, 0)
		}

		if err != nil {
			return nil, fmt.Errorf("fail to generate blum proof for [%d] due to error [%+v]", N, err)
		}
		Z_arr[i] = new(big.Int).Exp(y_arr[i], N_Inv, N)
	}

	return &PaillierBlumProof{W: w, X_arr: X_arr, A: A, B: B, Z_arr: Z_arr, M: m}, nil
}

func has_nil(proof *PaillierBlumProof) bool {
	if proof == nil {
		return true
	}
	if proof.A == nil || proof.B == nil || proof.W == nil || proof.X_arr == nil || proof.Z_arr == nil {
		return true
	}

	for i := range proof.X_arr {
		if proof.X_arr[i] == nil {
			return true
		}
	}

	for i := range proof.Z_arr {
		if proof.Z_arr[i] == nil {
			return true
		}
	}
	return false
}

type kSampleVerifyResult struct {
	sample_idx int
	verify     string
	err        error
}

func PaillierBlumVerify(N *big.Int, proof *PaillierBlumProof) error {
	if has_nil(proof) {
		return fmt.Errorf("proof [%+v] has a nil field. ", proof)
	}
	if N.Sign() <= 0 || N.Bit(0) == 0 || N.ProbablyPrime(100) {
		return fmt.Errorf("the N [%d] is not an positive odd prime. ", N)
	}

	if big.Jacobi(proof.W, N) != -1 {
		return fmt.Errorf("the Jacobi symbol of w [%d] is not -1", proof.W)
	}

	if new(big.Int).Mod(proof.W, N).Cmp(zero) == 0 {
		return fmt.Errorf("w [%d] mod N is 0", proof.W)
	}

	if proof.M < kMinSampleCount {
		return fmt.Errorf("the iteration [%d] is smaller than minimum required [%d]", proof.M, kMinSampleCount)
	}

	if len(proof.X_arr) < proof.M {
		return fmt.Errorf("x array is shorter than m [%d]", proof.M)
	}

	if len(proof.Z_arr) < proof.M {
		return fmt.Errorf("a array is shorter than m [%d]", proof.M)
	}

	if bitLen := proof.A.BitLen(); bitLen != proof.M+1 {
		return fmt.Errorf("the A's bit length [%d] is no greater than m [%d]", bitLen, proof.M)
	}

	if bitLen := proof.B.BitLen(); bitLen != proof.M+1 {
		return fmt.Errorf("the B's bit length [%d] is no greater than m [%d]", bitLen, proof.M)
	}

	y_arr := make([]*big.Int, proof.M)
	for i := 0; i < proof.M; i++ {
		e := oracle(proof.W, N, y_arr[0:i])
		y_arr[i] = new(big.Int).Mod(e, N)
	}

	chs := make(chan *kSampleVerifyResult, proof.M*2)
	for i := 0; i < proof.M; i++ {
		go func(i int, y *big.Int) {
			var err error = nil
			defer func() {
				chs <- &kSampleVerifyResult{
					sample_idx: i,
					verify:     "z^N ?= y mod N",
					err:        err,
				}
			}()
			z := proof.Z_arr[i]
			if new(big.Int).Mod(z, N) == zero {
				err = fmt.Errorf("z [%d] mod N [%d] == 0", z, N)
				return
			}
			left := new(big.Int).Exp(z, N, N)
			if left.Cmp(y_arr[i]) != 0 {
				err = fmt.Errorf("z^n [%d] != y[%d] mod N [%d] where z = [%d]", left, y, N, z)
				return
			}
		}(i, y_arr[i])

		go func(i int, x, w, y *big.Int) {
			var err error = nil
			defer func() {
				chs <- &kSampleVerifyResult{
					sample_idx: i,
					verify:     "x^4 ?= (-1)^a*(w)^b*y mod N",
					err:        err,
				}
			}()

			if new(big.Int).Mod(x, N) == zero {
				err = fmt.Errorf("x [%d] mod N [%d] == 0", x, N)
				return
			}

			a := proof.A.Bit(i)
			b := proof.B.Bit(i)
			if a != 0 && a != 1 {
				err = fmt.Errorf("a [%d] is not either 0 or 1", a)
				return
			}
			if b != 0 && b != 1 {
				err = fmt.Errorf("b [%d] is not either 0 or 1", b)
				return
			}
			left := new(big.Int).Exp(x, four, N)
			right := y
			if a > 0 {
				right = new(big.Int).Mul(big.NewInt(-1), right)
				right = right.Mod(right, N)
			}
			if b > 0 {
				right = new(big.Int).Mul(proof.W, right)
				right = right.Mod(right, N)
			}
			if left.Cmp(right) != 0 {
				err = fmt.Errorf("x^4 mod N = [%d] != (-1)^a*(w)^b*y = [%d] where a = [%d], b = [%d], x = [%d], N = [%d], w = [%d]", left, right, a, b, x, N, w)
				return
			}
		}(i, proof.X_arr[i], proof.W, y_arr[i])
	}

	for i := 0; i < proof.M*2; i++ {
		if result := <-chs; result.err != nil {
			return fmt.Errorf("verification fails on sample [%d] [%s] due to error [%v]", result.sample_idx, result.verify, result.err)
		}
	}

	return nil
}

func getQuarticRoot(N, phi, p, q, w, y *big.Int) (x *big.Int, a, b bool, err error) {
	// According 2.160 of https://cacr.uwaterloo.ca/hac/about/chap2.pdf, if y is a quadratic residual of blum integer, its square root of x = y^{(phi+4)/8} mod N.
	// Short explanation: any quadratic residual y of blum integer is a also of quatic residual. (See RPC internal sharing: https://okg-block.larksuite.com/docx/SIbFdDNuAoePUYxn8JFuaOr7s7c). Hence the y's order must divide phi/4, i.e., y^{phi/4}=1 mod N. In order to compute the fourth root of y, i.e., y^(1/4), we can first find 1/2 in group modular phi/4, that is, 1/2 + phi/8=(phi+4)/8, which is the square_root_exponent. Then the corresponding fourth_root_exponent is just the square of square_root_exponent. The fourth root is simply y^{square_root_exponent}.

	square_root_exponent := new(big.Int).Add(phi, big.NewInt(4))
	square_root_exponent = new(big.Int).Rsh(square_root_exponent, 3)
	fourth_root_exponent := new(big.Int).Mul(square_root_exponent, square_root_exponent)

	// below, by inspecting the jacobi symbol of y, w under p, q, we can know in advance which {y, -y, wy, -wy} is the quadratic residual.

	for j := 0; j < 4; j++ {
		// iterate (a, b) for (false, false), (true, false), (true, true), (false, true)
		a, b := j&1 == 1, j&2>>1 == 1
		y_tilt := new(big.Int).SetBytes(y.Bytes())
		if a {
			y_tilt = new(big.Int).Mul(big.NewInt(-1), y_tilt)
			y_tilt = new(big.Int).Mod(y_tilt, N)
		}
		if b {
			y_tilt = new(big.Int).Mul(w, y_tilt)
			y_tilt = new(big.Int).Mod(y_tilt, N)
		}
		// If big.Jacobi takes time, consider to use y^{(p-1)/2} to directly decide the quadratic residuality.
		if big.Jacobi(y_tilt, p) == 1 && big.Jacobi(y_tilt, q) == 1 {
			x := new(big.Int).Exp(y_tilt, fourth_root_exponent, N)

			return x, a, b, nil
		}
	}

	return nil, false, false, fmt.Errorf("fail to find a and b to make (-1)^a*(w)^b*y a quadratic residual for y [%d]", y)
}

func oracle(w, N *big.Int, y_arrs []*big.Int) *big.Int {
	return crypto.SHA256Int(append([]*big.Int{w, N}, y_arrs...)...)
}
