// distinguisher.go - Probabalistically identify newhope public keys.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

// IsProbablyNewHopePublicKey attempts to determine if a given byte string
// contains a NewHope public key by mounting a simple statistical attack
// against the polynomial.
//
// This is done by picking on the fact that `q = 12289` which is significantly
// less than 16383.  If the byte vector was truely random, the values between
// (q, (2^14 -1)] will appear at p ~= 0.24.  Since the polynomial contains 1024
// elements, the odds are overwelmingly in the favor of at least one sample
// falling into the target range (p > 0.999).
func IsProbablyNewHopePublicKey(r []byte) bool {
	if len(r) < PolyBytes {
		panic("invalid byte vector length")
	}

	var pk poly
	pk.fromBytes(r)

	for _, v := range pk.coeffs {
		if v > paramQ {
			return false
		}
	}

	return true
}
