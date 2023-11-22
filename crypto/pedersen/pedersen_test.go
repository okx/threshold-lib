package pedersen

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
)

func TestPedersen(t *testing.T) {
	parameters, _ := NewPedersenParameters(8)

	m := big.NewInt(10)
	r := big.NewInt(32)

	c1, _ := parameters.Commit(m, r)
	ok, _ := parameters.Open(c1, m, r)
	fmt.Println("ok", ok)

	ped, _ := json.Marshal(parameters)
	fmt.Println("ped", string(ped))

}
