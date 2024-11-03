package zkp

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/crypto/pedersen"
	"github.com/stretchr/testify/require"
)

func TestGroupElementPaillierEncryptionRangeProof(t *testing.T) {
	ped := &pedersen.PedersenParameters{}
	err := json.Unmarshal([]byte(pedParamsStr), ped)
	require.NoError(t, err)

	p, succ := new(big.Int).SetString(BlumPrimeP, 10)
	require.True(t, succ)
	q, succ := new(big.Int).SetString(BlumPrimeQ, 10)
	require.True(t, succ)

	N0 := new(big.Int).Mul(p, q)
	G := curves.ScalarToPoint(curve, big.NewInt(1))
	pubKey := paillier.PublicKey{N: N0}
	l := uint(16)

	x := crypto.RandomNum(new(big.Int).Lsh(one, l))
	X := G.ScalarMult(x)
	C, rho, err := pubKey.Encrypt(x)
	require.NoError(t, err)

	securtiy_params := &SecurityParameter{
		Q_bitlen: 64,
		Epsilon:  128,
	}

	t.Run("completeness", func(t *testing.T) {
		proof := NewGroupElementPaillierEncryptionRangeProof(N0, C, x, rho, l, X, G, ped, securtiy_params)
		require.True(t, GroupElementPaillierEncryptionRangeVerify(proof, ped))
	})

	t.Run("soundness", func(t *testing.T) {
		C, rho, err := pubKey.Encrypt(new(big.Int).Add(x, one))
		require.NoError(t, err)
		proof := NewGroupElementPaillierEncryptionRangeProof(N0, C, x, rho, l, X, G, ped, securtiy_params)
		r := GroupElementPaillierEncryptionRangeVerify(proof, ped)
		require.False(t, r)
	})

	t.Run("soundness_out_of_range", func(t *testing.T) {
		x := crypto.RandomNum(new(big.Int).Lsh(one, l+securtiy_params.Epsilon*2))
		X := G.ScalarMult(x)
		C, rho, err := pubKey.Encrypt(x)
		require.NoError(t, err)
		proof := NewGroupElementPaillierEncryptionRangeProof(N0, C, x, rho, l, X, G, ped, securtiy_params)
		r := GroupElementPaillierEncryptionRangeVerify(proof, ped)
		require.False(t, r)
	})
}
