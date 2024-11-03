package zkp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/okx/threshold-lib/crypto"
	"github.com/stretchr/testify/require"
)

func TestGetBlumPrimes(t *testing.T) {
	t.Skip()
	currency := 4
	var p, q *big.Int
	var values = make(chan *big.Int, currency)

	for p.Cmp(q) == 0 {
		var quit = make(chan int)
		for i := 0; i < currency; i++ {
			go crypto.GenerateSafePrime(1024, values, quit)
		}
		p, q = <-values, <-values
		close(quit)
	}
	require.Equal(t, new(big.Int).Mod(p, four).Cmp(new(big.Int).SetInt64(3)), 0)
	require.Equal(t, new(big.Int).Mod(q, four).Cmp(new(big.Int).SetInt64(3)), 0)
	t.Logf("p = [%d]", p)
	t.Logf("q = [%d]", q)
}

func TestGetNonBlumPrimes(t *testing.T) {
	t.Skip()
	currency := 4
	var p, q *big.Int
	var values = make(chan *big.Int, currency)

	for p.Cmp(q) == 0 {
		var quit = make(chan int)
		for i := 0; i < currency; i++ {
			go func() {
				for {
					select {
					case <-quit:
						return
					default:
						// this is to make it non-blocking
					}

					p, _ := rand.Prime(rand.Reader, 1024)
					if new(big.Int).Mod(p, four).Cmp(one) == 0 {
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
			}()
		}
		p, q = <-values, <-values
		close(quit)
	}
	require.Equal(t, new(big.Int).Mod(p, four).Cmp(new(big.Int).SetInt64(1)), 0)
	require.Equal(t, new(big.Int).Mod(q, four).Cmp(new(big.Int).SetInt64(1)), 0)
	t.Logf("p = [%d]", p)
	t.Logf("q = [%d]", q)
}

// below primes are all 1024 bit.
const BlumPrimeP = "135751741531138630212986367401440473273345553443240206900599775398484086842888950218156388524736127269745656746518539943387683515618105506449152508681861203638152551542315779705218077005283211144957273561287947835140306529354946028765560671699915629581808024606780437002804746279589409788279591036567260847227"
const BlumPrimeQ = "151458285289404559095250126289760184902419973267369170722482301171598360112355719472305547333766906244597020958615595692184779784507175332692351841265396728266455511450890511628195030937409161107049709530893185554561921286449431744046314846346879202144102087443741839967497005583531004939068822503717575212319"

const NonBlumPrimeP = "169929993462565787648440357096412083109074779189040706420177326232093238530645246717392399820501785129326737257845833667870161427766518596084130928936147300574196412406567345782664536689177520264345374133756396130214788776931822803442386520309771899400957782308345787106759153557021737635218975282049668623037"
const NonBlumPrimeQ = "163638125141705936165647294431896921245586156305192972604005809886467112179220961211434963533588119310255985936110568570692741863137020739423646947442874451468301847325323522299713865126966678319278016424047990157069857674841286927395219816634956882125178929130060037635217811929393743436750868019427544655357"

func TestPaillierBlumCompleteness(t *testing.T) {
	p, succ := new(big.Int).SetString(BlumPrimeP, 10)
	require.True(t, succ)
	q, succ := new(big.Int).SetString(BlumPrimeQ, 10)
	require.True(t, succ)

	n := new(big.Int).Mul(p, q)
	/* Benchmark result aarch m3: 16c32g
		--- PASS: TestPaillierBlumCompleteness/sample_count_40 (0.29s)
	    --- PASS: TestPaillierBlumCompleteness/sample_count_60 (0.42s)
	    --- PASS: TestPaillierBlumCompleteness/sample_count_80 (0.56s)
	*/
	for _, m := range []int{40, 60, 80} {
		t.Run(fmt.Sprintf("sample_count_%d", m), func(t *testing.T) {
			proof, err := PaillierBlumProve(n, p, q)
			require.NoError(t, err)
			err = PaillierBlumVerify(n, proof)
			require.NoError(t, err)
		})
	}
}

func TestPaillierBlumSoundness(t *testing.T) {
	p, succ := new(big.Int).SetString(BlumPrimeP, 10)
	require.True(t, succ)
	q, succ := new(big.Int).SetString(BlumPrimeQ, 10)
	require.True(t, succ)
	np, succ := new(big.Int).SetString(NonBlumPrimeP, 10)
	require.True(t, succ)
	nq, succ := new(big.Int).SetString(NonBlumPrimeQ, 10)
	require.True(t, succ)
	np_nq := new(big.Int).Mul(np, nq)
	p_nq := new(big.Int).Mul(p, nq)
	p_q := new(big.Int).Mul(p, q)

	t.Run("neither_p_q_blum", func(t *testing.T) {
		proof, err := PaillierBlumProve(np_nq, np, nq)
		if err != nil {
			// cannot find a quadratic y_tilt
		} else {
			// may find a quadratic y_tilt, but y_tilt is not a quartic, so the verification fails.
			err = PaillierBlumVerify(p_nq, proof)
			require.Error(t, err)
		}
	})
	t.Run("either_p_q_blum", func(t *testing.T) {
		proof, err := PaillierBlumProve(p_nq, p, nq)
		if err != nil {
			// cannot find a quadratic y_tilt
		} else {
			// may find a quadratic y_tilt, but y_tilt is not a quartic, so the verification fails.
			err = PaillierBlumVerify(p_nq, proof)
			require.Error(t, err)
		}
	})
	t.Run("not_enough_samples", func(t *testing.T) {
		proof, err := PaillierBlumProve(p_q, p, q)
		proof.M = 5
		require.NoError(t, err)
		err = PaillierBlumVerify(p_q, proof)
		require.Error(t, err)
	})
}
