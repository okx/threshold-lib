package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto/curves"
)

var label = []byte("Key share derivation:\n")

// support secp256k1 derived, not support ed25519
type TssKey struct {
	shareI       *big.Int        // key share
	publicKey    *curves.ECPoint // publicKey
	chaincode    []byte
	offsetSonPri *big.Int // child private key share offset, accumulative
}

// NewTssKey shareI is optional
func NewTssKey(shareI *big.Int, publicKey *curves.ECPoint, chaincode string) (*TssKey, error) {
	chainBytes, err := hex.DecodeString(chaincode)
	if err != nil {
		return nil, err
	}
	if publicKey == nil || chaincode == "" {
		return nil, fmt.Errorf("parameter error")
	}
	tssKey := &TssKey{
		shareI:       shareI,
		publicKey:    publicKey,
		chaincode:    chainBytes,
		offsetSonPri: big.NewInt(0),
	}
	return tssKey, nil
}

// NewChildKey like bip32 non-hardened derivation
func (tssKey *TssKey) NewChildKey(childIdx uint32) (*TssKey, error) {
	if childIdx >= uint32(0x80000000) { // 2^31
		return nil, fmt.Errorf("hardened derivation is unsupported")
	}
	curve := tssKey.publicKey.Curve
	intermediary, err := calPrivateOffset(tssKey.publicKey.X.Bytes(), tssKey.chaincode, childIdx)
	if err != nil {
		return nil, err
	}

	// Validate key
	err = validatePrivateKey(intermediary[:32])
	if err != nil {
		return nil, err
	}

	offset := new(big.Int).SetBytes(intermediary[:32])
	point := curves.ScalarToPoint(curve, offset)
	ecPoint, err := tssKey.publicKey.Add(point)
	if err != nil {
		return nil, err
	}
	shareI := tssKey.shareI
	if shareI != nil {
		shareI = new(big.Int).Add(shareI, offset)
		shareI = new(big.Int).Mod(shareI, curve.Params().N)
	}
	offsetSonPri := new(big.Int).Add(tssKey.offsetSonPri, offset)
	offsetSonPri = new(big.Int).Mod(offsetSonPri, curve.Params().N)
	tss := &TssKey{
		shareI:       shareI,
		publicKey:    ecPoint,
		chaincode:    intermediary[32:],
		offsetSonPri: offsetSonPri,
	}
	return tss, nil
}

// PrivateKeyOffset child share key offset, accumulative
func (tssKey *TssKey) PrivateKeyOffset() *big.Int {
	return tssKey.offsetSonPri
}

// ShareI child share key
func (tssKey *TssKey) ShareI() *big.Int {
	return tssKey.shareI
}

// PublicKey child publicKey
func (tssKey *TssKey) PublicKey() *curves.ECPoint {
	return tssKey.publicKey
}

// calPrivateOffset HMAC-SHA512(label | chaincode | publicKey | childIdx)
func calPrivateOffset(publicKey, chaincode []byte, childIdx uint32) ([]byte, error) {
	hash := hmac.New(sha512.New, label)
	var data []byte
	data = append(data, chaincode...)
	data = append(data, publicKey...)
	data = append(data, uint32Bytes(childIdx)...)
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func validatePrivateKey(key []byte) error {
	if fmt.Sprintf("%x", key) == "0000000000000000000000000000000000000000000000000000000000000000" || //if the key is zero
		bytes.Compare(key, secp256k1.S256().N.Bytes()) >= 0 || //or is outside of the curve
		len(key) != 32 { //or is too short
		return fmt.Errorf("Invalid private key")
	}
	return nil
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}
