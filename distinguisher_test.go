// distinguisher_test.go - Test probabalistic distinguisher.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestDistinguisher(t *testing.T) {
	for i := 0; i < 100; i++ {
		// Alice
		_, alicePub, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate alice's keypair: %v", err)
		}
		maybeNewHope := IsProbablyNewHopePublicKey(alicePub.Send[:])
		if maybeNewHope == false {
			t.Errorf("maybeNewHope: Alice false negative")
		}

		// Bob
		bobPub, _, err := KeyExchangeBob(rand.Reader, alicePub)
		if err != nil {
			t.Fatalf("failed Bob's PK operation: %v", err)
		}
		maybeNewHope = IsProbablyNewHopePublicKey(bobPub.Send[:])
		if maybeNewHope == false {
			t.Errorf("maybeNewHope: Bob false negative")
		}

		// Test a random byte vector.
		if _, err := io.ReadFull(rand.Reader, alicePub.Send[:]); err != nil {
			t.Fatalf("failed to generate random vector: %v", err)
		}
		maybeNewHope = IsProbablyNewHopePublicKey(alicePub.Send[:])
		if maybeNewHope == true {
			t.Errorf("maybeNewHope: false positive")
		}
	}
}
