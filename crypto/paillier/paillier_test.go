package paillier

import (
	"fmt"
	"math/big"
	"testing"
)

func TestPaillier(t *testing.T) {
	privateKey, publicKey, _ := NewKeyPair(8)

	num1 := big.NewInt(10)
	num2 := big.NewInt(32)
	c1, _, _ := publicKey.Encrypt(num1)
	c2, _, _ := publicKey.Encrypt(num2)
	ciphered, _ := publicKey.HomoAdd(c1, c2)

	plain, _ := privateKey.Decrypt(ciphered)
	fmt.Println(plain)

}
