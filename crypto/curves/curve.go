package curves

import (
	"crypto/elliptic"
	"reflect"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
)

const (
	Secp256k1 string = "secp256k1"
	Ed25519   string = "ed25519"
)

var curveMap map[string]elliptic.Curve

// only support ecdsa、ed25519
func init() {
	curveMap = map[string]elliptic.Curve{
		Secp256k1: secp256k1.S256(),
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
