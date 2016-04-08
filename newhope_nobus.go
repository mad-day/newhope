// newhope_nobus.go - Backdoored New Hope.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package newhope implements a key exchange based on the Ring Learning with
// Errors Problem.  It is a mechanical port of the Public Domain implementation
// by Erdem Alkim, Léo Ducas, Thomas Pöppelmann, and Peter Schwabe.
//
// For more information see: https://cryptojedi.org/papers/newhope-20151110.pdf
//
package newhope

//
// This is an example of a backdoored New Hope, in the style of A. Young and
// M. Yung's Kleptographic RSA backdoor.  It's inspired by the Elligator2
// based variant someone showed me (in the context of rigged TLS, because
// they used my library code).
//
// Alas, the backdoor is blatantly obvious on inspection, and reduces the
// security to approx 128 - 0.5 bits of classical and 0 post quantum security,
// so depending on how paranoid the nefarious forces of governmental evil are,
// other backdoor implementations should be considered.
//
// It is a NOBUS as recovering Alice's private key requires posessing the
// private component of the backdoor keypair.
//
// If it isn't blatantly obvious this is evil, and a perversion of the field,
// and should not be used ever.
//

import (
	"io"

	"git.schwanenlied.me/yawning/newhope.git/elligator2"
	"golang.org/x/crypto/curve25519"
)

// GenerateBackdooredKeyPair returns a private/public key pair, with a NOBUS
// backdoor.  The private key is generated using the given reader, which must
// return random data.  The receiver side of the key exchange (aka "Bob") MUST
// use KeyExchangeBob() instead of this routine, but has no effect on the
// impact of the primitive being backdoored (Alice still loses).
func GenerateBackdooredKeyPair(rand io.Reader, nsaPubKey *[32]byte) (*PrivateKeyAlice, *PublicKeyAlice, error) {
	var a, e, pk, r poly
	var seed, noiseSeed [SeedBytes]byte
	var nsaAlicePub, nsaAliceRepr, nsaAlicePriv [32]byte

	// The real algorithm does: seed <- Sample({0, 1}^256)
	//
	// Since this is backdoored,  we shall instead set the seed to
	// an Elligator2 representitive of a X25519 public key.
	if err := elligator2.GenerateKey(rand, &nsaAlicePub, &nsaAliceRepr, &nsaAlicePriv); err != nil {
		return nil, nil, err
	}
	defer memwipe(nsaAlicePriv[:])
	copy(seed[:], nsaAliceRepr[:])

	// a <- Parse(SHAKE-128(seed))
	a.uniform(&seed)

	// The real algorithm does:  s, e <- Sample(psi(n, 12))
	//
	// The second half of the backdoor (that makes key recovery possible)
	// is using the shared secret derived from  the NOBUS public key
	// (nsaPubKey) and the ephemeral keypair Alice generated as the noise
	// seed.
	curve25519.ScalarMult(&noiseSeed, &nsaAlicePriv, nsaPubKey)
	defer memwipe(noiseSeed[:])
	privKey := new(PrivateKeyAlice)
	privKey.sk.getNoise(&noiseSeed, 0)
	privKey.sk.ntt()
	e.getNoise(&noiseSeed, 1)
	e.ntt()

	// b <- as + e
	pubKey := new(PublicKeyAlice)
	r.pointwise(&privKey.sk, &a)
	pk.add(&e, &r)
	encodeA(pubKey.Send[:], &pk, &seed)

	return privKey, pubKey, nil
}

// RecoverBackdooredKey returns a private key from a public key generated with
// GenerateBackdooredKeyPair, and the backdoor private key.
func RecoverBackdooredKey(alicePub *PublicKeyAlice, nsaPrivKey *[32]byte) *PrivateKeyAlice {
	var pka poly
	var seed, noiseSeed [SeedBytes]byte
	var nsaAlicePub [32]byte

	// The seed is an Elligator2 representative, extract it, and reverse the
	// transform to get the backdoor X25519 session key.
	decodeA(&pka, &seed, alicePub.Send[:])
	elligator2.RepresentativeToPublicKey(&nsaAlicePub, &seed)

	// The noise seed is the shared secret derived from the backdoor private
	// key and the backdoor session key (recovered from seed).
	curve25519.ScalarMult(&noiseSeed, nsaPrivKey, &nsaAlicePub)

	// Reconstruct Alice's private key.
	privKey := new(PrivateKeyAlice)
	privKey.sk.getNoise(&noiseSeed, 0)
	privKey.sk.ntt()

	return privKey
}
