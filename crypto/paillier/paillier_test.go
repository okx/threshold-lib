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
	one, _ := publicKey.Encrypt(num1)
	two, _ := publicKey.Encrypt(num2)
	ciphered, _ := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)
	fmt.Println(plain)

}

func TestNIZK(t *testing.T) {
	privateKey, publicKey, _ := NewKeyPair(8)

	proof, _ := NIZKProof(privateKey.N, privateKey.Phi)
	fmt.Println(proof)

	verify := NIZKVerify(publicKey.N, proof)
	fmt.Println(verify)
}
