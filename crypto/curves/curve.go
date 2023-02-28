package curves

import (
	"crypto/elliptic"
	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"reflect"
)

const (
	Secp256k1 string = "secp256k1"
	Ed25519   string = "ed25519"
)

var curveMap map[string]elliptic.Curve

// only support ecdsa、ed25519
func init() {
	curveMap = map[string]elliptic.Curve{
		Secp256k1: btcec.S256(),
		Ed25519:   edwards.Edwards(),
	}
}

func GetCurveByName(curveName string) elliptic.Curve {
	return curveMap[curveName]
}

func GetCurveName(curve elliptic.Curve) string {
	for name, e := range curveMap {
		if reflect.TypeOf(curve) == reflect.TypeOf(e) {
			return name
		}
	}
	return ""
}
