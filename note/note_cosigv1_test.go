// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"filippo.io/mldsa"
	"golang.org/x/mod/sumdb/note"
)

func TestSignerRoundtrip(t *testing.T) {
	edSk, _ := mustGenerateEd25519Key(t, "ed25519")
	mlSk, _ := mustGenerateMLDSAKey(t, "mldsa")

	for _, test := range []struct {
		name string
		skey string
	}{
		{
			name: "ed25519",
			skey: edSk,
		},
		{
			name: "mldsa",
			skey: mlSk,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, err := NewSignerForCosignatureV1(test.skey)
			if err != nil {
				t.Fatal(err)
			}

			msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
			n, err := note.Sign(&note.Note{Text: msg}, s)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := note.Open(n, note.VerifierList(s.Verifier())); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFormatMLDSASignatureV1(t *testing.T) {
	for _, test := range []struct {
		name         string
		cosignerName string
		logOrigin    string
		wantErr      bool
	}{
		{
			name:         "ok",
			cosignerName: "mldsa",
			logOrigin:    "test",
		},
		{
			name:         "origin name too long",
			cosignerName: "mldsa",
			logOrigin:    strings.Repeat("t", 256),
			wantErr:      true,
		},
		{
			name:         "cosigner name too long",
			cosignerName: "mldsa" + strings.Repeat("a", 255),
			logOrigin:    "test",
			wantErr:      true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := sha256.Sum256([]byte("blah"))
			_, err := formatMLDSACosignatureV1(test.cosignerName, 0, test.logOrigin, 0, 0, root[:])
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("formatMLDSACosignatureV1: got %v", err)
			}
		})
	}
}

func TestCosignatureV1RoundTrip(t *testing.T) {
	edSk, edPk := mustGenerateEd25519Key(t, "ed25519")
	mlSk, mlPk := mustGenerateMLDSAKey(t, "mldsa")
	for _, test := range []struct {
		name string
		skey string
		vkey string
	}{
		{
			name: "ed25519",
			skey: edSk,
			vkey: edPk,
		},
		{
			name: "mldsa",
			skey: mlSk,
			vkey: mlPk,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, err := NewSignerForCosignatureV1(test.skey)
			if err != nil {
				t.Fatal(err)
			}

			v, err := NewVerifierForCosignatureV1(test.vkey)
			if err != nil {
				t.Fatal(err)
			}

			msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
			n, err := note.Sign(&note.Note{Text: msg}, s)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("s.KeyHash(): %08x, v.KeyHash(): %08x", s.KeyHash(), v.KeyHash())

			if _, err := note.Open(n, note.VerifierList(v)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifierInvalidSig(t *testing.T) {
	skey, _, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
	if _, err := note.Sign(&note.Note{Text: msg}, s); err != nil {
		t.Fatal(err)
	}

	if _, err := note.Open([]byte("nobbled"), note.VerifierList(s.Verifier())); err == nil {
		t.Fatal("Verifier validated incorrect signature")
	}
}

func TestSigCoversExtensionLines(t *testing.T) {
	skey, _, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\nExtendo\n"
	n, err := note.Sign(&note.Note{Text: msg}, s)
	if err != nil {
		t.Fatal(err)
	}

	n[len(n)-2] = '@'
	if _, err := note.Open(n, note.VerifierList(s.Verifier())); err == nil {
		t.Fatal("Signature did not cover extension lines")
	}
}

func TestCoSigV1NewVerifier(t *testing.T) {
	for _, test := range []struct {
		name    string
		pubK    string
		wantErr bool
	}{
		{
			name: "works: convert from algEd25519",
			pubK: "TEST+7997405c+AQcC+FTVKf0jlTdHDY3rbevmnKxxPjigCXlVtGe6RIr6",
		}, {
			name: "works: native algEd25519CosignatureV1 verifier",
			pubK: "remora.n621.de+da77ade7+BOvN63jn/bLvkieywe8R6UYAtVtNbZpXh34x7onlmtw2",
		}, {
			name: "works: native algMLDSA44 verifier",
			pubK: "test+5893dc2c+BtMcFiao6ZOdU6LZ40tLKbsWpDOU8smRapXBIYI3lXyESm62to+/AeDuWOEtbwUNVzrC9FacZ1q+gXES2hAhp5/C1TPwTiO/G+T9x0iAb8gSGkGwsbDJXmQMhsFM+Ub3tB5Fdujz4o7DF3NqCCUMC1zsD7jMyy9BTCFi6Av1I/ZDRQxJJOKFt31l0cJY6OHFcUGMSGSHcGEo839UikbMBlArWRgYk/Ve4aqW0pRl7G46Qk39pu/yFYwhk3gMYMkush5NKQo7EbvhnHvUlQWK27t2VsIbH2p/l9i73UDtEmHeqIMcqtwhCnFoqT6S7cL9/p7NLwxD1gICM0gCZIi3KrbnMFok+5uovBbrF9vISSXX67R1nprdjiE0MGAwZ3Prtt0ah2xchT5I1WgmUGSA0B1cnEDXWneUaA0axw/TQ47x88+jfKIN0kn8rg5bncI5q71hV2mF1n2xuE4G+WOdBRjMVGLWlt1rZcCh8IredoZe3SxWKx7amrLo00lFN8QL8TAw1bvDiFYRqyAZE4Z5M77H8OmAR2QahuZA+d8Q1SXmTdDtOu1RRXtHq54Nm3d2SbQl48UE7BsWvu7YdqGEti5EpTX3oMVmnnjj0FRH2QjlnpaRn5bE8tiblhL31f6KRz37E9lqIUoLuE19OQ+yYOj2B6avwEY6xWq5SrOOhENQKAODXTjacDYVL4Z1hsJA9+7qbFH5S3JjMCs4VFtZHOa4tkxbpO94lfPNnhqDnuFb5xm7sT51/In+xn0vAyCoaaIpm/rwG0nRFZmR6bafSPBJXcnrocdPy86sQ/C3ma7ldByWwsHuEm8YTNABAqn6hNICNECFuoV8EBwnA0BVkhClyjTkPSnyB1CAUEkzQwd/SW7VgjDoI9r6k4ot1oaxD9ZudZor7309jhMIbQhE1ODPMDxFM2B5XvhlJ6nl6r0JUI/q2uLnZGyzKDMGnL+T+uGDN+AvBrg4kyHEM1X39Dkr1XpJIMRlROY+GayJliTQ8eEdZ1yug5C0JGHJ9bEQu/L2Zf084+/+4BAUrrJ4JtmShbYulaDmMVjm72Osu5a9ld7KeZ2hn5uK9yhiUJqeBDGGLmqqZbbUwIRa9OWZoQVU+dCt2ust5migCq69O3H+83U2YKBj9r3QLv6FG/crj3IUrKagKIqv5fT71eeCEmSmdAGqVP+5hxBQMBcISqp+9rqDsS1NLba2YuUWYgFDlQ7Xq915t+d3N5ouHNWJHs1/2V0ZNsSvID1p73sUWVJlh2M4/B8/QT1uvteCPc+yycsJM80Xaomwv9KTfUpyNn60R860zr+Va432W8v5urT1Teu6QCTWKdq3ivhyYREBLvka07jb7SlIees2PKDfvibKBBanF/EmorgkdPIagG/88kT9GtXtOIQp/HJLw3Ej5QPwEgrLYZ0YY6t53ZC6BmjDt0eSEShPmqte74KC7Qgo2hvA3grqp03vA7RG3cMCmtn/k0PH9ZY4ytTF7eozJCRim9AWa0HudpkGKbv3ijxrkBBhAGTCGQe96Tt5nBiKatheV3z4i2o4TtoRC6SEQZUEnWLszXOWtghhfe/V7QqB8jfMLxHW2qkueUkTz2IatYI+2hlkyTQRIKGPjKrnF8qAKz5/PZcoaL6pBaWcpsUEcpwQs6/aT0tmB2UGZNzrj02lREEgGajjuqHMH/rwmqIQTV38KohBniPDkDV9jdIyU1HVlm5dElah29WMC+RWC6bN2GbOvn1+s6iQwNNLUGU=",
		}, {
			name:    "wrong number of parts",
			pubK:    "bananas.sigstore.dev+12344556",
			wantErr: true,
		}, {
			name:    "invalid base64",
			pubK:    "rekor.sigstore.dev+12345678+THIS_IS_NOT_BASE64!",
			wantErr: true,
		}, {
			name:    "invalid algo",
			pubK:    "rekor.sigstore.dev+12345678+AwEB",
			wantErr: true,
		}, {
			name:    "invalid keyhash",
			pubK:    "rekor.sigstore.dev+NOT_A_NUMBER+" + sigStoreKeyMaterial,
			wantErr: true,
		}, {
			name:    "incorrect keyhash",
			pubK:    "rekor.sigstore.dev+00000000+" + sigStoreKeyMaterial,
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewVerifier(test.pubK)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("NewVerifier(%q): %v", test.pubK, err)
			}
		})
	}
}

func TestCoSigV1Timestamp(t *testing.T) {
	for _, test := range []struct {
		name     string
		sig      note.Signature
		wantErr  bool
		wantTime time.Time
	}{
		{
			name:     "works",
			sig:      note.Signature{Base64: "ZGhGuQAAAABm/qTPeyKXD+R2rzyQsxPiP8mXum7qq/iF0u4vanlqJyocWODBt97w9uL+8qT7S5gxEHWWOworDcFiEBYJXORmnFBOBA=="},
			wantTime: time.Unix(1727964367, 0).UTC(),
		}, {
			name:    "wrong type of signature",
			sig:     note.Signature{Base64: "eQjRQm6eSKzFoiYalgwCPXu2y3ijtg68is9M46JKxuZB+dRfTmeQeDBoXnvxZx2ugnkyV+MUMLXpWs1hPb/W/4xkNQY="},
			wantErr: true,
		}, {
			name:    "gibberish",
			sig:     note.Signature{Base64: "5%/$!\n 2"},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotTime, err := CoSigV1Timestamp(test.sig)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("got error %q, want err: %v", err, test.wantErr)
			} else if gotErr {
				return
			}
			if gotTime != test.wantTime {
				t.Fatalf("got time %v, want %v", gotTime, test.wantTime)
			}
		})
	}
}

func TestCosignatureTimestamp(t *testing.T) {
	for _, test := range []struct {
		name     string
		sig      note.Signature
		wantErr  bool
		wantTime uint64
	}{
		{
			name:     "works",
			sig:      note.Signature{Base64: "ZGhGuQAAAABm/qTPeyKXD+R2rzyQsxPiP8mXum7qq/iF0u4vanlqJyocWODBt97w9uL+8qT7S5gxEHWWOworDcFiEBYJXORmnFBOBA=="},
			wantTime: 1727964367,
		}, {
			name:    "wrong type of signature",
			sig:     note.Signature{Base64: "eQjRQm6eSKzFoiYalgwCPXu2y3ijtg68is9M46JKxuZB+dRfTmeQeDBoXnvxZx2ugnkyV+MUMLXpWs1hPb/W/4xkNQY="},
			wantErr: true,
		}, {
			name:    "gibberish",
			sig:     note.Signature{Base64: "5%/$!\n 2"},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotTime, err := CosignatureTimestamp(test.sig)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("got error %q, want err: %v", err, test.wantErr)
			} else if gotErr {
				return
			}
			if gotTime != test.wantTime {
				t.Fatalf("got time %v, want %v", gotTime, test.wantTime)
			}
		})
	}
}

func TestVKeyToCosignatureV1(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "TestKey")
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	cosigner, err := NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatalf("Failed to create cosignerv1: %v", err)
	}
	covkey, err := VKeyToCosignatureV1(vkey)
	if err != nil {
		t.Fatalf("Failed to convert vkey to cosigv1 verifier: %v", err)
	}
	workingVKeys := []string{
		vkey,
		covkey,
	}
	n, err := note.Sign(&note.Note{Text: "Note\n\n"}, cosigner)
	if err != nil {
		t.Fatalf("Failed to sign note: %v", err)
	}
	for _, k := range workingVKeys {
		coverifier, err := NewVerifierForCosignatureV1(k)
		if err != nil {
			t.Errorf("Failed to create verifier from %q: %v", k, err)
			continue
		}
		if _, err = note.Open(n, note.VerifierList(coverifier)); err != nil {
			t.Errorf("Failed to open note with verifier %q: %v", k, err)
		}
	}

	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("Failed to create standard verifier: %v", err)
	}
	// Now check that the standard vkey cannot open a cosig signature.
	if _, err = note.Open(n, note.VerifierList(v)); err == nil {
		t.Errorf("Expected error trying to open cosigned note with standard vkey, but got success")
	}

	// Check that VKeyToCosignatureV1 fails for MLDSA keys.
	_, mlVkey := mustGenerateMLDSAKey(t, "mldsa")
	if _, err := VKeyToCosignatureV1(mlVkey); err == nil {
		t.Errorf("Expected error for MLDSA key in VKeyToCosignatureV1, got success")
	}
}

func TestSubtreeRoundtrip(t *testing.T) {
	skey, vkey := mustGenerateMLDSAKey(t, "mldsa")

	signer, err := NewMLDSASigner(skey)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewMLDSAVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}

	origin := "test-log"
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		desc       string
		start, end uint64
		wantErr    bool
	}{
		{
			desc:  "from zero",
			start: 0,
			end:   10,
		},
		{
			desc:  "non-zero power-of-two size",
			start: 8,
			end:   16,
		},
		{
			desc:  "non-zero partial subtree",
			start: 8,
			end:   13,
		},
		{
			desc:  "empty subtree",
			start: 10,
			end:   10,
		},
		{
			desc:    "invalid: start > end",
			start:   10,
			end:     8,
			wantErr: true,
		},
		{
			desc:    "invalid: misaligned subtree",
			start:   2,
			end:     6,
			wantErr: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			sig, err := signer.SignSubtree(origin, test.start, test.end, root)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("SignSubtree(%d, %d): got err %v, wantErr %v", test.start, test.end, err, test.wantErr)
			}
			if test.wantErr {
				return
			}

			if !verifier.VerifySubtree(origin, test.start, test.end, root, sig) {
				t.Errorf("Failed to verify valid subtree signature %x", sig)
			}

			// Test failure cases
			wrongRoot := make([]byte, 32)
			wrongRoot[0] = root[0] ^ 1
			if verifier.VerifySubtree(origin, test.start, test.end, wrongRoot, sig) {
				t.Error("VerifySubtree succeeded with wrong root")
			}

			if verifier.VerifySubtree("wrong origin", test.start, test.end, root, sig) {
				t.Error("VerifySubtree succeeded with wrong origin")
			}

			if verifier.VerifySubtree(origin, test.start+1, test.end, root, sig) {
				t.Error("VerifySubtree succeeded with wrong start")
			}

			if verifier.VerifySubtree(origin, test.start, test.end+1, root, sig) {
				t.Error("VerifySubtree succeeded with wrong end")
			}

			corruptedSig := append([]byte(nil), sig...)
			corruptedSig[0] ^= 1
			if verifier.VerifySubtree(origin, test.start, test.end, root, corruptedSig) {
				t.Error("VerifySubtree succeeded with corrupted signature")
			}
		})
	}
}

func TestIsSubtreeValid(t *testing.T) {
	// Includes test vectors from draft-ietf-plants-merkle-tree-certs-07 Appendix C.2.1.
	for _, test := range []struct {
		desc       string
		start, end uint64
		want       bool
	}{
		{
			desc:  "empty at 0",
			start: 0,
			end:   0,
			want:  true,
		},
		{
			desc:  "empty at non-zero",
			start: 42,
			end:   42,
			want:  true,
		},
		{
			desc:  "valid [4, 8)",
			start: 4,
			end:   8,
			want:  true,
		},
		{
			desc:  "valid [8, 13)",
			start: 8,
			end:   13,
			want:  true,
		},
		{
			desc:  "valid [0, 2^47 + 1)",
			start: 0,
			end:   (1 << 47) + 1,
			want:  true,
		},
		{
			desc:  "valid [0, 2^48 - 1)",
			start: 0,
			end:   (1 << 48) - 1,
			want:  true,
		},
		{
			desc:  "valid [0, 2^62 + 1)",
			start: 0,
			end:   (1 << 62) + 1,
			want:  true,
		},
		{
			desc:  "valid [0, 2^63 - 1)",
			start: 0,
			end:   (1 << 63) - 1,
			want:  true,
		},
		{
			desc:  "valid [0, 2^63 + 1)",
			start: 0,
			end:   (1 << 63) + 1,
			want:  true,
		},
		{
			desc:  "valid [0, 2^64 - 1)",
			start: 0,
			end:   ^uint64(0),
			want:  true,
		},
		{
			desc:  "valid [2^63, 2^64 - 1)",
			start: 1 << 63,
			end:   ^uint64(0),
			want:  true,
		},
		{
			desc:  "invalid: start > end",
			start: 10,
			end:   8,
			want:  false,
		},
		{
			desc:  "invalid: misaligned [2, 6)",
			start: 2,
			end:   6,
			want:  false,
		},
		{
			desc:  "invalid: misaligned [4, 9)",
			start: 4,
			end:   9,
			want:  false,
		},
		{
			desc:  "invalid: [2^46, 2^47 + 1)",
			start: 1 << 46,
			end:   (1 << 47) + 1,
			want:  false,
		},
		{
			desc:  "invalid: [2^46, 2^48 - 1)",
			start: 1 << 46,
			end:   (1 << 48) - 1,
			want:  false,
		},
		{
			desc:  "invalid: [2^61, 2^62 + 1)",
			start: 1 << 61,
			end:   (1 << 62) + 1,
			want:  false,
		},
		{
			desc:  "invalid: [2^61, 2^63 - 1)",
			start: 1 << 61,
			end:   (1 << 63) - 1,
			want:  false,
		},
		{
			desc:  "invalid: [2^62, 2^63 + 1)",
			start: 1 << 62,
			end:   (1 << 63) + 1,
			want:  false,
		},
		{
			desc:  "invalid: [2^62, 2^64 - 1)",
			start: 1 << 62,
			end:   ^uint64(0),
			want:  false,
		},
		{
			desc:  "invalid: size == 2^63 with non-zero start",
			start: 1,
			end:   (1 << 63) + 1,
			want:  false,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			if got := isSubtreeValid(test.start, test.end); got != test.want {
				t.Errorf("isSubtreeValid(%d, %d) = %v, want %v", test.start, test.end, got, test.want)
			}
		})
	}
}

func TestGenerateMLDSAKey(t *testing.T) {
	for _, test := range []struct {
		name    string
		wantErr bool
	}{
		{
			name: "valid",
		},
		{
			name:    "invalid name",
			wantErr: true,
		},
		{
			name:    "name-too-long" + strings.Repeat("g", 255),
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			skey, vkey, err := GenerateMLDSAKey(test.name)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("GenerateMLDSASignerKey(%q) error = %v, wantErr %v", test.name, err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			// Roundtrip check
			s, err := NewMLDSASigner(skey)
			if err != nil {
				t.Fatalf("NewMLDSASigner(%q): %v", skey, err)
			}
			v, err := NewMLDSAVerifier(vkey)
			if err != nil {
				t.Fatalf("NewMLDSAVerifier(%q): %v", vkey, err)
			}
			if s.Name() != test.name {
				t.Errorf("Signer name = %q, want %q", s.Name(), test.name)
			}
			if v.Name() != test.name {
				t.Errorf("Verifier name = %q, want %q", v.Name(), test.name)
			}
			if s.KeyHash() != v.KeyHash() {
				t.Errorf("Signer hash %08x != Verifier hash %08x", s.KeyHash(), v.KeyHash())
			}
		})
	}
}

func mustGenerateEd25519Key(t *testing.T, name string) (string, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	return skey, vkey
}

func mustGenerateMLDSAKey(t *testing.T, name string) (string, string) {
	t.Helper()
	skey, vkey, err := GenerateMLDSAKey(name)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey(%q): %v", name, err)
	}
	return skey, vkey
}

func TestMLDSASignerFromCrypto(t *testing.T) {
	const name = "mldsa-test"

	for _, test := range []struct {
		name    string
		signer  crypto.Signer
		wantErr bool
	}{
		{
			name:   "valid MLDSA signer",
			signer: mustMLDSASigner(t),
		},
		{
			name:    "invalid signer (not MLDSA)",
			signer:  mustECDSASigner(t),
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer, err := NewMLDSASignerFromCrypto(name, test.signer)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("NewMLDSASignerFromCrypto: got err %v, wantErr %v", err, test.wantErr)
			}
			if test.wantErr {
				return
			}

			if signer.Name() != name {
				t.Errorf("signer.Name() = %q, want %q", signer.Name(), name)
			}

			origin := "test-log"
			var start uint64 = 0
			var end uint64 = 10
			root := make([]byte, 32)
			if _, err := rand.Read(root); err != nil {
				t.Fatal(err)
			}
			sig, err := signer.SignSubtree(origin, start, end, root)
			if err != nil {
				t.Fatalf("SignSubtree: %v", err)
			}

			verifier := signer.Verifier()
			if !verifier.VerifySubtree(origin, start, end, root, sig) {
				t.Fatal("Failed to verify valid subtree signature")
			}
		})
	}
}

func TestMLDSAVerifyTorchwood(t *testing.T) {
	// Key & Signature generated by filippo.io/torchwood
	// https://go.dev/play/p/tT09aD1mdMl
	vkey := "witness.example/w1+a0d0cd91+Bhh6t5zW2IMElD4GJw65/1+GnMosGFhPFst8+uCD+C9/lSovRbjzbFPV7YP9rox2T9pHbsqNmvR3GTnwSFLUZIatFUlXBt0CGLU1J75PMs7G1KNj5yL4R8vvInpzaDvlBUoCLjzegUOh7KImnowtDnJRX38puLf1mStewbP61oBYZmIlWhXproauXnBl0VGbqbd8qeLQ96ENJBhFATSuxbQoJZ3dhGwkHnEQUlqHdEPgYXKwuMWfzKz4X+54eDV4c+IOFcU3/Lmis2aqAG0LoAM4X+eE569R0YVmjXdybbqrCx6dc8gwM9DZp7+gUBwWtI6ccaXJoN6kmdPBC6qUv/PHlCaFCNq170DqAbFJauGRUOBKjGyP9mSQaF6yoNrkdEOsSh039J1uaqDD7X+g5KxFWwM+R1X2HibnEW6okJaIM+MaPsAnZeQLPYbaup/2emXDsHj58+b/5S03DRszJJStFlNxHnMTe+aNyj7vbU8/GD5B3T4es6HsvNbF5+w0PRmZ/1Kkkad4+D6aFj7pMU8eVCpMZtdU8zlYcHOyNZssna8mTL11jfq9NpD5wSo+CYAiDZ/hrW9QjUYpqwzUVTr9gN14mBXfax1g9iTxRAId1ZaHBoYqyitNpE2/797iJVEshYXeh49wGPsPUp+GQYUvYVGr0CmtEYEBoXXDYechA+G1dSyKGgeU5R5ufOkLnumvHW060RKxst3eXKMi1uNyEojsTUhHclL44a6irz95MAWE4k7d9E3Tu8S6mct5WVN4TzyFKZ7PPB+mIMhsbg6n5lI62D3gMKGHTJGbGz17iNZwj0FVp5trL4OGiF6qeK2FLXesOlWYOfOFXvfuLZXvNwmry3aSi/ST+65qXHmAGLQ0ip06A8yEUt3zGZ2VI8whagfAXj2CxcFcPVgg9KI+0aJnbldm6KYcaLoI+fs1iyGQ+zgXrejm/hCyGik+JFVfZGlH+hirnNNglxRsJzIYsFT73ss3+29SnAduHZOYFqLs1aNsDytZgEhC37EL8vqIO7jY1MR8ihldBljWiVV+AQiWpyKvseP5SFP82pcfkGi6DbAAQmifLjGGcm9pCqDIUWrXIyiwt/WbtTgzEuQhdtuYEFeK59BSdpXW9UxUAYG8AjlYL+ylVUjbtz9CYGHtaCoi3NxkaRaUZj2Mtx2WQSyDI2uUTUwOpiqVwJEAE3lpOBqHV58hEosDfAxR1A0bw7px4LFqsfuFcapsP1015sb2IIQn8zx8lfIVtTon2jYMyANqACceBA43Vu9+o7ij+wwEVedRsO5d6/F6KZjL+weSiaIzGRQUazSvkMGZr+3rgaol3wgHkBY/AvJRPqxEZA14+e+HVl7rOTR96o20g72AoDnTj+V5LpggrDEd2eJeYR+1SjphxPKE+Y4U4NJ/Zv68Cji9lmIXAo9ohBGxcjkPdw2Ha2HTE0WT3HwROtbBeFfEvKaAkke9VS5fGmPqkLXzuBmZ4OsRM5zwhW0mcZUjWp4anpuSyngVddL3NyTUg2UBoU3sQVAKr/VtboY0Fn6LuSi+jS6IXUhNkTfHEkZXnWN1oYnQs46/iWbJk0NxjPaCIYceU7DZTLpCuPOVRgm31FcF0AZT/T40gbgzAu7isTXhlOtswI0dpT9k2FidQPsrZh9QZr1lZjcyzqt0M2PeYcctUYY/Y75T5ZNBxxmgQ/EDwu6Y1RUAk9xa7ZrIeJ2ZHXGgwIT7yDQoj8c0nlb/k1qqMbqQey/63s4="

	cp := "example.com/log\n15\nE7ERCtFloiK1fdb+B6/dLG0pM1nmIR0ETKBSauCjtVw=\n\n— witness.example/w1 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\n"

	v, err := NewMLDSAVerifier(vkey)
	if err != nil {
		t.Fatalf("Invalid vkey: %v", err)
	}

	if _, err := note.Open([]byte(cp), note.VerifierList(v)); err != nil {
		t.Fatalf("Failed to verify valid note: %v", err)
	}
}

func TestMLDSAVerifySubtreeTorchwood(t *testing.T) {
	// Key & Signature generated by filippo.io/torchwood
	// https://go.dev/play/p/tT09aD1mdMl
	vkey := "witness.example/w1+a0d0cd91+Bhh6t5zW2IMElD4GJw65/1+GnMosGFhPFst8+uCD+C9/lSovRbjzbFPV7YP9rox2T9pHbsqNmvR3GTnwSFLUZIatFUlXBt0CGLU1J75PMs7G1KNj5yL4R8vvInpzaDvlBUoCLjzegUOh7KImnowtDnJRX38puLf1mStewbP61oBYZmIlWhXproauXnBl0VGbqbd8qeLQ96ENJBhFATSuxbQoJZ3dhGwkHnEQUlqHdEPgYXKwuMWfzKz4X+54eDV4c+IOFcU3/Lmis2aqAG0LoAM4X+eE569R0YVmjXdybbqrCx6dc8gwM9DZp7+gUBwWtI6ccaXJoN6kmdPBC6qUv/PHlCaFCNq170DqAbFJauGRUOBKjGyP9mSQaF6yoNrkdEOsSh039J1uaqDD7X+g5KxFWwM+R1X2HibnEW6okJaIM+MaPsAnZeQLPYbaup/2emXDsHj58+b/5S03DRszJJStFlNxHnMTe+aNyj7vbU8/GD5B3T4es6HsvNbF5+w0PRmZ/1Kkkad4+D6aFj7pMU8eVCpMZtdU8zlYcHOyNZssna8mTL11jfq9NpD5wSo+CYAiDZ/hrW9QjUYpqwzUVTr9gN14mBXfax1g9iTxRAId1ZaHBoYqyitNpE2/797iJVEshYXeh49wGPsPUp+GQYUvYVGr0CmtEYEBoXXDYechA+G1dSyKGgeU5R5ufOkLnumvHW060RKxst3eXKMi1uNyEojsTUhHclL44a6irz95MAWE4k7d9E3Tu8S6mct5WVN4TzyFKZ7PPB+mIMhsbg6n5lI62D3gMKGHTJGbGz17iNZwj0FVp5trL4OGiF6qeK2FLXesOlWYOfOFXvfuLZXvNwmry3aSi/ST+65qXHmAGLQ0ip06A8yEUt3zGZ2VI8whagfAXj2CxcFcPVgg9KI+0aJnbldm6KYcaLoI+fs1iyGQ+zgXrejm/hCyGik+JFVfZGlH+hirnNNglxRsJzIYsFT73ss3+29SnAduHZOYFqLs1aNsDytZgEhC37EL8vqIO7jY1MR8ihldBljWiVV+AQiWpyKvseP5SFP82pcfkGi6DbAAQmifLjGGcm9pCqDIUWrXIyiwt/WbtTgzEuQhdtuYEFeK59BSdpXW9UxUAYG8AjlYL+ylVUjbtz9CYGHtaCoi3NxkaRaUZj2Mtx2WQSyDI2uUTUwOpiqVwJEAE3lpOBqHV58hEosDfAxR1A0bw7px4LFqsfuFcapsP1015sb2IIQn8zx8lfIVtTon2jYMyANqACceBA43Vu9+o7ij+wwEVedRsO5d6/F6KZjL+weSiaIzGRQUazSvkMGZr+3rgaol3wgHkBY/AvJRPqxEZA14+e+HVl7rOTR96o20g72AoDnTj+V5LpggrDEd2eJeYR+1SjphxPKE+Y4U4NJ/Zv68Cji9lmIXAo9ohBGxcjkPdw2Ha2HTE0WT3HwROtbBeFfEvKaAkke9VS5fGmPqkLXzuBmZ4OsRM5zwhW0mcZUjWp4anpuSyngVddL3NyTUg2UBoU3sQVAKr/VtboY0Fn6LuSi+jS6IXUhNkTfHEkZXnWN1oYnQs46/iWbJk0NxjPaCIYceU7DZTLpCuPOVRgm31FcF0AZT/T40gbgzAu7isTXhlOtswI0dpT9k2FidQPsrZh9QZr1lZjcyzqt0M2PeYcctUYY/Y75T5ZNBxxmgQ/EDwu6Y1RUAk9xa7ZrIeJ2ZHXGgwIT7yDQoj8c0nlb/k1qqMbqQey/63s4="

	sig := "— witness.example/w1 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\n"

	v, err := NewMLDSAVerifier(vkey)
	if err != nil {
		t.Fatalf("Invalid vkey: %v", err)
	}

	// TODO(al): At time of writing, torchwood produces note-style subtree signatures,
	// so we'll parse out the raw signature ourselves for now.
	_, sig, _ = strings.Cut(sig, " ") // Chomp the dash
	_, sig, _ = strings.Cut(sig, " ") // Chomp the name

	// Everything else should be base64 encoded.
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("Invalid signature: %v", err)
	}
	// Drop keyhash (4 bytes) and timestamp (8 bytes)
	sigBytes = sigBytes[4+8:]

	if len(sigBytes) != mldsa.MLDSA44SignatureSize {
		t.Fatalf("Invalid signature length: %d", len(sigBytes))
	}

	o := "example.com/log"
	s, e := uint64(8), uint64(16)
	h := sha256.Sum256([]byte("test"))
	if !v.VerifySubtree(o, s, e, h[:], sigBytes) {
		t.Fatalf("Failed to verify valid subtree signature")
	}
}

func mustMLDSASigner(t *testing.T) crypto.Signer {
	t.Helper()
	mldsaK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	return mldsaK
}

func mustECDSASigner(t *testing.T) crypto.Signer {
	t.Helper()
	ecdsaK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ecdsaK
}
