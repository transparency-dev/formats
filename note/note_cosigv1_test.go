// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
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

func TestMLDSASignerVerifierRoundtrip(t *testing.T) {
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

func TestSignerVerifierRoundtrip(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVerifierForCosignatureV1(vkey)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
	n, err := note.Sign(&note.Note{Text: msg}, s)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := note.Open(n, note.VerifierList(v)); err != nil {
		t.Fatal(err)
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
			pubK:    "rekor.sigstore.dev" + "+" + "00000000" + "+" + sigStoreKeyMaterial,
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
			wantTime: time.Unix(1727964367, 0),
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
				t.Fatalf("got time %v, want %v", gotTime.UnixMilli(), test.wantTime.UnixMilli())
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
	var start uint64 = 0
	var end uint64 = 10
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	timestamp := uint64(time.Now().Unix())

	sig, err := signer.SignSubtree(timestamp, origin, start, end, root)
	if err != nil {
		t.Fatal(err)
	}

	if !verifier.VerifySubtree(timestamp, origin, start, end, root, sig) {
		t.Error("Failed to verify valid subtree signature")
	}

	// Test failure cases
	wrongRoot := make([]byte, 32)
	wrongRoot[0] = 1
	if verifier.VerifySubtree(timestamp, origin, start, end, wrongRoot, sig) {
		t.Error("VerifySubtree succeeded with wrong root")
	}

	if verifier.VerifySubtree(timestamp, "wrong origin", start, end, root, sig) {
		t.Error("VerifySubtree succeeded with wrong origin")
	}
}

func TestMLDSAInvalidTimestamp(t *testing.T) {
	skey, _ := mustGenerateMLDSAKey(t, "mldsa")
	signer, err := NewMLDSASigner(skey)
	if err != nil {
		t.Fatal(err)
	}

	origin := "test-log"
	var start uint64 = 10 // > 0
	var end uint64 = 20
	root := make([]byte, 32)
	timestamp := uint64(time.Now().Unix()) // > 0

	_, err = signer.SignSubtree(timestamp, origin, start, end, root)
	if err == nil {
		t.Error("Expected error for invalid timestamp (start > 0 && timestamp > 0), got nil")
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
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("Failed to generate MLDSA key: %v", err)
	}
	privBytes := key.Bytes()
	pubBytes := key.PublicKey().Bytes()

	pubKeyWithAlg := append([]byte{algMLDSA44}, pubBytes...)
	hash := keyHashMLDSA(name, pubKeyWithAlg)

	skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, hash, base64.StdEncoding.EncodeToString(append([]byte{algMLDSA44}, privBytes...)))
	vkey := fmt.Sprintf("%s+%08x+%s", name, hash, base64.StdEncoding.EncodeToString(pubKeyWithAlg))
	return skey, vkey
}
