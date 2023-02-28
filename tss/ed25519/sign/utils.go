package sign

import "math/big"

// bigIntToEncodedBytes converts a big integer into its corresponding
// 32 byte little endian representation.
func bigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}
	// Caveat: a can be longer than 32 bytes.
	s = copyBytes(a.Bytes())
	// Reverse the byte string --> little endian after encoding.
	reverse(s)
	return s
}

// encodedBytesToBigInt converts a 32 byte little endian representation of
// an integer into a big, big endian integer.
func encodedBytesToBigInt(s *[32]byte) *big.Int {
	// Use a copy so we don't screw up our original memory.
	sCopy := new([32]byte)
	for i := 0; i < 32; i++ {
		sCopy[i] = s[i]
	}
	reverse(sCopy)
	bi := new(big.Int).SetBytes(sCopy[:])
	return bi
}

// reverse reverses a byte string.
func reverse(s *[32]byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// copyBytes copies a byte slice to a 32 byte array.
func copyBytes(aB []byte) *[32]byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)
	// If we have a short byte string, expand it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 32 {
		diff := 32 - len(aB)
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}
	for i := 0; i < 32; i++ {
		s[i] = aB[i]
	}
	return s
}
