// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/mldsa"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

const (
	algEd25519              = 1
	algECDSAWithSHA256      = 2
	algEd25519CosignatureV1 = 4
	algRFC6962STH           = 5
	algMLDSA44							= 6
)

const (
	keyHashSize   = 4
	timestampSize = 8
)

// NewSignerForCosignatureV1 constructs a new Signer that produces timestamped
// cosignature/v1 signatures using the provided skey-formated key.
//
// Supported skey algorithms are:
// - a standard Ed25519 encoded signer key (algo ID 0x01)
// - an Ed25519 cosignature/v1 encoded signer key (algo ID 0x04)
// - an ML-DSA-44 cosignature/v1 encoded signer key (algo ID 0x06)
//
// See https://c2sp.org/tlog-cosignature for more details.
func NewSignerForCosignatureV1(skey string) (*Signer, error) {
	priv1, skey, _ := strings.Cut(skey, "+")
	priv2, skey, _ := strings.Cut(skey, "+")
	name, skey, _ := strings.Cut(skey, "+")
	hash16, key64, _ := strings.Cut(skey, "+")
	key, err := base64.StdEncoding.DecodeString(key64)
	if priv1 != "PRIVATE" || priv2 != "KEY" || len(hash16) != 8 || err != nil || !isValidName(name) || len(key) == 0 {
		return nil, errSignerID
	}

	s := &Signer{name: name}

	alg, key := key[0], key[1:]
	switch alg {
	default:
		return nil, errSignerAlg

	case algEd25519, algEd25519CosignatureV1:
		if len(key) != ed25519.SeedSize {
			return nil, errSignerID
		}
		key := ed25519.NewKeyFromSeed(key)
		pubkey := append([]byte{algEd25519CosignatureV1}, key.Public().(ed25519.PublicKey)...)
		s.hash = keyHashEd25519(name, pubkey)
		s.sign = func(msg []byte) ([]byte, error) {
			t := uint64(time.Now().Unix())
			m, err := formatEd25519CosignatureV1(t, msg)
			if err != nil {
				return nil, err
			}

			// The signature itself is encoded as timestamp || signature.
			sig := make([]byte, 0, timestampSize+ed25519.SignatureSize)
			sig = binary.BigEndian.AppendUint64(sig, t)
			sig = append(sig, ed25519.Sign(key, m)...)
			return sig, nil
		}
		s.verify = verifyEd25519CosigV1(pubkey[1:])
		
	case algMLDSA44:
		if len(key) != mldsa.PrivateKeySize {
			return nil, errSignerID
		}
		key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), key)
		if err != nil {
			return nil, err
		}
		pubkey := append([]byte{algMLDSA44}, key.PublicKey().Bytes()...)
		s.hash = keyHashMLDSA(name, pubkey)
		s.sign = func(msg []byte) ([]byte, error) {
			t := uint64(time.Now().Unix())
			m, err := formatMLDSACosignatureV1(name, t, msg)
			if err != nil {
				return nil, err
			}
			sB, err := key.Sign(nil, m, nil)
			if err != nil {
				return nil, err
			}

			// The signature itself is encoded as timestamp || signature.
			sig := make([]byte, 0, timestampSize+mldsa.MLDSA44SignatureSize)
			sig = binary.BigEndian.AppendUint64(sig, t)
			sig = append(sig, sB...)
			return sig, nil
		}
		s.verify = verifyMLDSACosigV1(key.PublicKey(), name)
	}

	return s, nil
}

// NewVerifierForCosignatureV1 constructs a new Verifier for timestamped
// cosignature/v1 signatures from the provided vkey-formatted public key.
// 
// Supported vkey types are:
// - a standard Ed25519 verifier key (type 0x01)
// - an Ed25519 CosignatureV1 key (type 0x04)
// - an ML-DSA-44 CosignatureV1 key (type 0x06)
//
// Note: If a standard Ed25519 verifier key (type 0x01) is provided, it will 
// be internally treated as an Ed25519 CosignatureV1 key (type 0x04), meaning 
// the returned Verifier has a different key hash from a non-timestamped Ed25519 
// verifier key.
func NewVerifierForCosignatureV1(vkey string) (note.Verifier, error) {
	name, vkey, _ := strings.Cut(vkey, "+")
	hash16, key64, _ := strings.Cut(vkey, "+")
	key, err := base64.StdEncoding.DecodeString(key64)
	if len(hash16) != 8 || err != nil || !isValidName(name) || len(key) == 0 {
		return nil, errVerifierID
	}

	v := &verifier{
		name: name,
	}

	alg, key := key[0], key[1:]
	switch alg {
	default:
		return nil, errVerifierAlg

	case algEd25519, algEd25519CosignatureV1:
		if len(key) != 32 {
			return nil, errVerifierID
		}
		v.keyHash = keyHashEd25519(name, append([]byte{algEd25519CosignatureV1}, key...))
		v.v = verifyEd25519CosigV1(key)

	case algMLDSA44:
		if len(key) != mldsa.MLDSA44PublicKeySize {
			return nil, errVerifierID
		}
		v.keyHash = keyHashMLDSA(name, append([]byte{algMLDSA44}, key...))
		pubKey, err := mldsa.NewPublicKey(mldsa.MLDSA44(), key)
		if err != nil {
			return nil, err
		}
		v.v = verifyMLDSACosigV1(pubKey, name)
	}

	return v, nil
}

// VKeyToCosignatureV1 converts a standard Ed25519 vkey to an Ed25519CosignatureV1 vkey.
func VKeyToCosignatureV1(vkey string) (string, error) {
	name, vkey, _ := strings.Cut(vkey, "+")
	hash16, key64, _ := strings.Cut(vkey, "+")
	algKey, err := base64.StdEncoding.DecodeString(key64)
	if len(hash16) != 8 || err != nil || !isValidName(name) || len(algKey) == 0 {
		return "", errVerifierID
	}

	alg, key := algKey[0], algKey[1:]
	if alg != algEd25519 {
		return "", errVerifierAlg
	}
	hash, err := strconv.ParseUint(hash16, 16, 32)
	if err != nil {
		return "", errInvalidHash
	}

	if uint32(hash) != keyHashEd25519(name, algKey) {
		return "", errInvalidHash
	}
	if len(key) != 32 {
		return "", errVerifierID
	}
	pubKey := append([]byte{algEd25519CosignatureV1}, key...)
	h := keyHashEd25519(name, pubKey)

	return fmt.Sprintf("%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(pubKey)), nil
}

// CoSigV1Timestamp extracts the embedded timestamp from a CoSigV1 signature.
func CoSigV1Timestamp(s note.Signature) (time.Time, error) {
	r, err := base64.StdEncoding.DecodeString(s.Base64)
	if err != nil {
		return time.UnixMilli(0), errMalformedSig
	}
	const minSigSize = 64 // min(ed25519.SignatureSize, mldsa.MLDSA44SignatureSize)
	if len(r) < keyHashSize+timestampSize+minSigSize {
		return time.UnixMilli(0), errVerifierAlg
	}
	r = r[keyHashSize:] // Skip the hash
	// Next 8 bytes are the timestamp as Unix seconds-since-epoch:
	return time.Unix(int64(binary.BigEndian.Uint64(r)), 0), nil
}

// verifyEd25519CosigV1 returns a verify function based on key.
func verifyEd25519CosigV1(key []byte) func(msg, sig []byte) bool {
	return func(msg, sig []byte) bool {
		if len(sig) != timestampSize+ed25519.SignatureSize {
			return false
		}
		t := binary.BigEndian.Uint64(sig)
		sig = sig[timestampSize:]
		m, err := formatEd25519CosignatureV1(t, msg)
		if err != nil {
			return false
		}
		return ed25519.Verify(key, m, sig)
	}
}

// verifyMLDSACosigV1 returns a verify function based on key and cosigner name.
func verifyMLDSACosigV1(pubKey *mldsa.PublicKey, name string) func(msg, sig []byte) bool {
	return func(msg, sig []byte) bool {
		if len(sig) != timestampSize+mldsa.MLDSA44SignatureSize {
			return false
		}
		t := binary.BigEndian.Uint64(sig)
		sig = sig[timestampSize:]
		m, err := formatMLDSACosignatureV1(name, t, msg)
		if err != nil {
			return false
		}
		return mldsa.Verify(pubKey, m, sig, nil) == nil
	}
}

func formatEd25519CosignatureV1(t uint64, msg []byte) ([]byte, error) {
	// The signed message is in the following format:
	//
	//      cosignature/v1
	//      time TTTTTTTTTT
	//      origin line
	//      NNNNNNNNN
	//      tree hash
	//      ...
	//
	// where TTTTTTTTTT is the current UNIX timestamp, and the following
	// lines are the lines of the note.
	//
	// While the witness signs all lines of the note, it's important to
	// understand that the witness is asserting observation of correct
	// append-only operation of the log based on the first three lines;
	// no semantic statement is made about any extra "extension" lines.
	//
	// See https://c2sp.org/tlog-cosignature for more details.

	if lines := bytes.Split(msg, []byte("\n")); len(lines) < 3 {
		return nil, errors.New("cosigned note format invalid")
	}
	return []byte(fmt.Sprintf("cosignature/v1\ntime %d\n%s", t, msg)), nil
}

func formatMLDSACosignatureV1(cosignerName string, t uint64, msg []byte) ([]byte, error) {
	// The signed message is a binary TLS presentation encoding of the
	// following structure:
	//     struct {
	//        uint8 label[12] = "subtree/v1\n\0"; 
	//        opaque cosigner_name<1..2^8-1>;
	//        uint64 timestamp;
	//        opaque log_origin<1..2^8-1>; 
	//        uint64 start;
	//        uint64 end;
	//        uint8 hash[32];
	//    } cosigned_message;
	
	lines := bytes.Split(msg, []byte("\n"))
	if len(lines) < 3 {
		return nil, errors.New("cosigned note format invalid")
	}
	logOrigin := lines[0]
	size, err := strconv.ParseUint(string(lines[1]), 10, 64)
	if err != nil {
		return nil, errors.New("size line malformed")
	}
	hash, err := base64.StdEncoding.DecodeString(string(lines[2]))
	if err != nil {
		return nil, errors.New("hash line malformed")
	}
	if len(hash) != sha256.Size {
		return nil, errors.New("hash line must be 32 bytes")
	}

	r := cryptobyte.NewFixedBuilder(make([]byte, 0, 12+(2+len(cosignerName))+8+(2+len(logOrigin))+8+8+32))
	r.AddBytes([]byte("subtree/v1\n\x00"))
	r.AddUint8(uint8(len(cosignerName)))
	r.AddBytes([]byte(cosignerName))
	r.AddUint64(t) // timestamp
	r.AddUint8(uint8(len(logOrigin)))
	r.AddBytes(logOrigin)
	r.AddUint64(0) // start
	r.AddUint64(size) // end
	r.AddBytes(hash)
	return r.Bytes()
}

var (
	errSignerID     = errors.New("malformed signer id")
	errSignerAlg    = errors.New("unknown signer algorithm")
	errVerifierID   = errors.New("malformed verifier id")
	errVerifierAlg  = errors.New("unknown verifier algorithm")
	errInvalidHash  = errors.New("invalid key hash")
	errMalformedSig = errors.New("malformed signature")
)

type Signer struct {
	name   string
	hash   uint32
	sign   func([]byte) ([]byte, error)
	verify func(msg, sig []byte) bool
}

func (s *Signer) Name() string                    { return s.name }
func (s *Signer) KeyHash() uint32                 { return s.hash }
func (s *Signer) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }

func (s *Signer) Verifier() note.Verifier {
	return &verifier{
		name:    s.name,
		keyHash: s.hash,
		v:       s.verify,
	}
}

// isValidName reports whether name is valid.
// It must be non-empty and not have any Unicode spaces or pluses.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHashEd25519(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

func keyHashMLDSA(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}
