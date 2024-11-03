package keygen

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/crypto/pedersen"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/crypto/zkp"
	"github.com/okx/threshold-lib/tss"
)

var (
	curve = secp256k1.S256()
	G     = curves.ScalarToPoint(curve, big.NewInt(1))
)

type PreParams struct {
	NTildei     *big.Int
	H1i, H2i    *big.Int
	Alpha, Beta *big.Int
	P, Q        *big.Int
}

type PreParamsWithDlnProof struct {
	Params *PreParams
	Proof  *zkp.DlnProof
}

// GeneratePreParams recommend to pre-generate locally
func GeneratePreParamsWithDlnProof() *PreParamsWithDlnProof {
	concurrency := 4
	var values = make(chan *big.Int, concurrency)
	var Pi, Qi *big.Int
	for Pi == Qi {
		var quit = make(chan int)
		for i := 0; i < concurrency; i++ {
			go crypto.GenerateSafePrime(1024, values, quit)
		}
		Pi, Qi = <-values, <-values
		close(quit)
	}

	NTildei := new(big.Int).Mul(Pi, Qi)
	// Compute pi = (Pi-1)/2, qi = (Qi-1)/2
	pi := new(big.Int).Rsh(Pi, 1)
	qi := new(big.Int).Rsh(Qi, 1)

	pq := new(big.Int).Mul(pi, qi)
	f1 := crypto.RandomNum(NTildei)
	alpha := crypto.RandomNum(NTildei)
	beta := new(big.Int).ModInverse(alpha, pq)

	// h1i = f^2 mod tildeNi, h2i = h1i^alpha mod tildeNi
	h1i := new(big.Int).Mod(new(big.Int).Mul(f1, f1), NTildei)
	h2i := new(big.Int).Exp(h1i, alpha, NTildei)

	preParams := &PreParams{
		NTildei: NTildei,
		H1i:     h1i,
		H2i:     h2i,
		Alpha:   alpha,
		Beta:    beta,
		P:       pi,
		Q:       qi,
	}
	proof1 := zkp.NewDlnProve(h1i, h2i, alpha, pi, qi, NTildei)
	return &PreParamsWithDlnProof{
		Params: preParams,
		Proof:  proof1,
	}
}

func (p *PreParamsWithDlnProof) PedersonParameters() *pedersen.PedersenParameters {
	return &pedersen.PedersenParameters{
		S:      p.Params.H2i,
		T:      p.Params.H1i,
		Ntilde: p.Params.NTildei,
	}
}

func (p *PreParamsWithDlnProof) Verify() bool {
	return zkp.DlnVerify(p.Proof, p.Params.H1i, p.Params.H2i, p.Params.NTildei)
}

type P1Data struct {
	E_x1      *big.Int // paillier encrypt x1
	Proof     *schnorr.Proof
	PaiPubKey *paillier.PublicKey // paillier public key
	X1        *curves.ECPoint

	NoSmallFactorProof *zkp.NoSmallFactorProof
	BlumProof          *zkp.PaillierBlumProof
	X1RangeProof       *zkp.GroupElementPaillierEncryptionRangeProof
	DlnProof           *zkp.DlnProof
	Ped1               *pedersen.PedersenParameters
}

// P1 after dkg, prepare for 2-party signature, P1 send encrypt x1 to P2
// RPC: paillier key pair generation is time-consuming, generated in advance, encrypted storage?
func P1(share1 *big.Int, paiPriKey *paillier.PrivateKey, from, to int, preParamsAndProof *PreParamsWithDlnProof, p2_ped *pedersen.PedersenParameters, p2_dlnproof *zkp.DlnProof) (*tss.Message, *big.Int, error) {
	if !zkp.DlnVerify(p2_dlnproof, p2_ped.T, p2_ped.S, p2_ped.Ntilde) {
		return nil, nil, fmt.Errorf("fail to verify dln proof for p2 pederson parameters. ")
	}
	// lagrangian interpolation x1
	x1 := vss.CalLagrangian(curve, big.NewInt(int64(from)), share1, []*big.Int{big.NewInt(int64(from)), big.NewInt(int64(to))})
	paiPubKey := &paiPriKey.PublicKey
	// paillier encrypt x1
	E_x1, r, err := paiPubKey.Encrypt(x1)
	if err != nil {
		return nil, nil, err
	}
	// schnorr prove x1
	X1 := curves.ScalarToPoint(curve, x1)
	proof, err := schnorr.Prove(x1, X1)
	if err != nil {
		return nil, nil, err
	}

	security_params := &zkp.SecurityParameter{
		Q_bitlen: 64,
		Epsilon:  128,
	}
	// PDLwSlackStatement
	q_bitlen := uint(X1.Curve.Params().N.BitLen())
	X1RangeProof := zkp.NewGroupElementPaillierEncryptionRangeProof(
		paiPriKey.N, E_x1, x1, r, q_bitlen, X1, G, p2_ped, security_params,
	)
	l := uint(16)
	securty_params := &zkp.SecurityParameter{
		Q_bitlen: 64,
		Epsilon:  128,
	}
	noSmallFactorProof := zkp.NoSmallFactorProve(paiPriKey.N, paiPriKey.P, paiPriKey.Q, l, p2_ped, securty_params)
	blumProof, err := zkp.PaillierBlumProve(paiPriKey.N, paiPriKey.P, paiPriKey.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to generate blum proof due to error [%w]", err)
	}

	p1Data := P1Data{
		E_x1:               E_x1,
		Proof:              proof,
		PaiPubKey:          paiPubKey,
		X1:                 X1,
		NoSmallFactorProof: noSmallFactorProof,
		BlumProof:          blumProof,
		Ped1:               preParamsAndProof.PedersonParameters(),
		DlnProof:           preParamsAndProof.Proof,
		X1RangeProof:       X1RangeProof,
	}

	bytes, err := json.Marshal(p1Data)
	if err != nil {
		return nil, nil, err
	}
	message := &tss.Message{
		From: from,
		To:   to,
		Data: string(bytes),
	}
	return message, E_x1, nil
}
