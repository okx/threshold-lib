package keygen

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
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

// GeneratePreParams  recommend to pre-generate locally
func GeneratePreParams() *PreParams {
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
	return preParams
}

type P1Data struct {
	E_x1      *big.Int // paillier encrypt x1
	Proof     *schnorr.Proof
	PaiPubKey *paillier.PublicKey // paillier public key
	X1        *curves.ECPoint

	NIZKProof       []string
	DlnProof1       *zkp.DlnProof
	DlnProof2       *zkp.DlnProof
	PDLwSlackProof  *zkp.PDLwSlackProof
	StatementParams *zkp.StatementParams
}

// P1 after dkg, prepare for 2-party signature, P1 send encrypt x1 to P2
// paillier key pair generation is time-consuming, generated in advance, encrypted storage?
func P1(share1 *big.Int, paiPriKey *paillier.PrivateKey, from, to int, preParams *PreParams) (*tss.Message, error) {
	// lagrangian interpolation x1
	x1 := vss.CalLagrangian(curve, big.NewInt(int64(from)), share1, []*big.Int{big.NewInt(int64(from)), big.NewInt(int64(to))})
	paiPubKey := &paiPriKey.PublicKey
	// paillier encrypt x1
	E_x1, r, err := paiPubKey.Encrypt(x1)
	if err != nil {
		return nil, err
	}
	// schnorr prove x1
	X1 := curves.ScalarToPoint(curve, x1)
	proof, err := schnorr.Prove(x1, X1)
	if err != nil {
		return nil, err
	}
	nizkProof, err := paillier.NIZKProof(paiPriKey.N, paiPriKey.Phi)
	if err != nil {
		return nil, err
	}

	if preParams == nil {
		preParams = GeneratePreParams()
	}
	h1i, h2i, alpha, beta, p, q, NTildei :=
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.Beta,
		preParams.P,
		preParams.Q,
		preParams.NTildei
	// zkp DlnProof
	dlnProof1 := zkp.NewDlnProve(h1i, h2i, alpha, p, q, NTildei)
	dlnProof2 := zkp.NewDlnProve(h2i, h1i, beta, p, q, NTildei)

	// PDLwSlackStatement
	pdlWSlackWitness := &zkp.PDLwSlackWitness{
		X: x1,
		R: r,
	}
	pdlWSlackStatement := &zkp.PDLwSlackStatement{
		N:          paiPubKey.N,
		CipherText: E_x1,
		Q:          X1,
		G:          G,
		H1:         h1i,
		H2:         h2i,
		NTilde:     NTildei,
	}
	pdlWSlackPf, statementParams := zkp.NewPDLwSlackProve(pdlWSlackWitness, pdlWSlackStatement)
	if pdlWSlackPf == nil || statementParams == nil {
		return nil, fmt.Errorf("PDLwSlack proof fail")
	}

	p1Data := P1Data{
		E_x1:            E_x1,
		Proof:           proof,
		PaiPubKey:       paiPubKey,
		X1:              X1,
		NIZKProof:       nizkProof,
		DlnProof1:       dlnProof1,
		DlnProof2:       dlnProof2,
		PDLwSlackProof:  pdlWSlackPf,
		StatementParams: statementParams,
	}
	bytes, err := json.Marshal(p1Data)
	if err != nil {
		return nil, err
	}
	message := &tss.Message{
		From: from,
		To:   to,
		Data: string(bytes),
	}
	return message, nil
}
