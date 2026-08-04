// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"strconv"
	"encoding/base64"
	"golang.org/x/mod/sumdb/note"
)

// These algorithm identifiers correspond to those in https://c2sp.org/signed-note@v1.0.0
const (
	algEd25519              = 1
	algECDSAWithSHA256      = 2
	algEd25519CosignatureV1 = 4
	algRFC6962STH           = 5
	algMLDSA44              = 6
)

const (
	// keyHashSize is the size in bytes of the key hash.
	keyHashSize = 4
)

var (
	errSignerID         = errors.New("malformed signer id")
	errSignerAlg        = errors.New("unknown signer algorithm")
	errVerifierID       = errors.New("malformed verifier id")
	errVerifierAlg      = errors.New("unknown verifier algorithm")
	errInvalidHash      = errors.New("invalid key hash")
	errMalformedSig     = errors.New("malformed signature")
	errSignerHash		= errors.New("invalid verifier hash")
)

// NewSigner returns a new Signer for keys with the following algorithms:
// - 0x01 The original SumDB Note ed25519 algorithm.
// - 0x04 ed25519 Cosignature/V1
// - 0x06 ML-DSA-44 Cosignature/V1
func NewSigner(skey string) (Signer, error) {
	priv1, skey, _ := strings.Cut(skey, "+")
	priv2, skey, _ := strings.Cut(skey, "+")
	name, skey, _ := strings.Cut(skey, "+")
	hash16, key64, _ := strings.Cut(skey, "+")
	key, err := base64.StdEncoding.DecodeString(key64)
	if priv1 != "PRIVATE" || priv2 != "KEY" || len(hash16) != 8 || err != nil || !isValidName(name) || len(key) == 0 {
		return nil, errSignerID
	}

	alg, key := key[0], key[1:]
	switch alg {
	case algEd25519:
		// We "re-implement" this here so as to be able to return a local Signer instance (as
		// opposed to a note.Signer).
		// This has the benefit that all signers from this package carry a Verifier() getter.

		// Adapted from sumdb/note/note.go
		hash, err := strconv.ParseUint(hash16, 16, 32)
		if err != nil {
			return nil, errSignerID
		}

		// Note: hash is the hash of the public key and we have the private key.
		// Must verify hash after deriving public key.

		s := &signer{
			name: name,
			hash: uint32(hash),
		}
		if len(key) != 32 {
			return nil, errSignerID
		}
		key = ed25519.NewKeyFromSeed(key)
		pubkey := append([]byte{algEd25519}, key[32:]...)
		if uint32(hash) != keyHashEd25519(name, pubkey) {
			return nil, errSignerHash
		}

		s.sign = func(msg []byte) ([]byte, error) {
			return ed25519.Sign(key, msg), nil
		}
		s.verify = func(msg, sig []byte) bool {
			return ed25519.Verify(key, msg, sig)
		}

		return s, nil
	case algEd25519CosignatureV1, algMLDSA44:
		return NewSignerForCosignatureV1(skey)
	default:
		return nil, errSignerAlg
	}
}

// The structs below are used by most/all of the signers and verifiers in this package.

// Signer is a note.Signer which also provides access to the corresponding Verifier.
type Signer interface {
	note.Signer
	Verifier() note.Verifier
}

// signer is a concrete implementation of the extended Signer interface above.
type signer struct {
	name   string
	hash   uint32
	sign   func([]byte) ([]byte, error)
	verify func(msg, sig []byte) bool
}

func (s *signer) Name() string                    { return s.name }
func (s *signer) KeyHash() uint32                 { return s.hash }
func (s *signer) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }

func (s *signer) Verifier() note.Verifier {
	return &verifier{
		name:    s.name,
		keyHash: s.hash,
		v:       s.verify,
	}
}

// NewVerifier returns a verifier for the given key, if the key's algo is known.
func NewVerifier(key string) (note.Verifier, error) {
	parts := strings.SplitN(key, "+", 3)
	if got, want := len(parts), 3; got != want {
		return nil, fmt.Errorf("key has %d parts, expected %d: %q", got, want, key)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("key has invalid base64 %q: %v", parts[2], err)
	}
	if len(keyBytes) < 2 {
		return nil, fmt.Errorf("invalid key, key bytes too short")
	}

	switch keyBytes[0] {
	case algECDSAWithSHA256:
		return NewECDSAVerifier(key)
	case algEd25519CosignatureV1, algMLDSA44:
		return NewVerifierForCosignatureV1(key)
	case algRFC6962STH:
		return NewRFC6962Verifier(key)
	default:
		return note.NewVerifier(key)
	}
}

// verifier is a note-compatible verifier.
type verifier struct {
	name    string
	keyHash uint32
	v       func(msg, sig []byte) bool
}

// Name returns the name associated with the key this verifier is based on.
func (v *verifier) Name() string {
	return v.name
}

// KeyHash returns a truncated hash of the key this verifier is based on.
func (v *verifier) KeyHash() uint32 {
	return v.keyHash
}

// Verify checks that the provided sig is valid over msg for the key this verifier is based on.
func (v *verifier) Verify(msg, sig []byte) bool {
	return v.v(msg, sig)
}


