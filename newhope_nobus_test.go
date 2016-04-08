// newhope_nobus_test.go - Backdoored New Hope tests.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestBackdoor(t *testing.T) {
	// The NSA generates a X25519 keypair.
	//
	// The private key is kept in the bottom of a locked filing cabinet
	// stuck in a disused lavatory with a sign on the door saying beware
	// of the leopard.
	//
	// The public key which is hardcoded into the application that uses
	// the crooked New Hope implementation.
	//
	// For purposes of illustration this will just generate a new keypair.
	var nsaPubKey, nsaPrivKey [32]byte

	if _, err := io.ReadFull(rand.Reader, nsaPrivKey[:]); err != nil {
		t.Fatalf("Eve: failed to generate NOBUS private key: %v", err)
	}
	curve25519.ScalarBaseMult(&nsaPubKey, &nsaPrivKey)

	// Alice runs the backdoored key generation algorithm, and handshakes
	// with Bob like normal.
	alicePrivKey, alicePubKey, err := GenerateBackdooredKeyPair(rand.Reader, &nsaPubKey)
	if err != nil {
		t.Fatalf("Alice: failed to generate key pair: %v", err)
	}

	// Bob handshakes with Alice like normal, with an unsubverted copy of the
	// code.
	bobPubKey, bobShared, err := KeyExchangeBob(rand.Reader, alicePubKey)
	if err != nil {
		t.Fatalf("Bob: failed to handshake: %v", err)
	}

	// Alice completes the handshake, and derives a shared secret used to
	// initialize session keys/whatever.
	aliceShared, err := KeyExchangeAlice(bobPubKey, alicePrivKey)
	if err != nil {
		t.Fatalf("Alice: failed to handshaake: %v", err)
	}

	// Sanity check.  Alice/Bob arrived at the same keys.
	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatalf("Alice/Bob: shared secrets mismatch")
	}

	// Eve captures both sides of the exchange, and stashes the session
	// traffic in her datacenter in Utah, and has an analyst recover Alice's
	// private key using the backdoor private key.
	nsaAlicePriv := RecoverBackdooredKey(alicePubKey, &nsaPrivKey)

	// Eve completes Alice's side of the handshake, since she has Alice's
	// private key, and wins.
	nsaAliceShared, err := KeyExchangeAlice(bobPubKey, nsaAlicePriv)
	if err != nil {
		t.Fatalf("Eve: failed to handshake: %v", err)
	}

	// See, Eve posesses the shared secret.
	if !bytes.Equal(aliceShared, nsaAliceShared) {
		t.Fatalf("Eve: shared secrets mismatch")
	}
}
