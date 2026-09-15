// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
			_, err := formatMLDSACosignatureV1(test.cosignerName, 0, test.logOrigin, 0, 0, []byte{})
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
	timestamp := time.Now().Truncate(time.Second)

	sig, err := signer.SignSubtree(uint64(timestamp.Unix()), origin, start, end, root)
	if err != nil {
		t.Fatal(err)
	}

	if !verifier.VerifySubtree(origin, start, end, root, sig) {
		t.Fatalf("Failed to verify valid subtree signature %q", sig)
	}
	if gotTimestamp, err := SubtreeTimestamp(sig); err != nil {
		t.Fatalf("Failed to extract timestamp from signature: %v", err)
	} else if gotTimestamp != timestamp {
		t.Fatalf("Signature timestamp %v != expected timestamp %v", gotTimestamp, timestamp)
	}

	// Test failure cases
	wrongRoot := make([]byte, 32)
	wrongRoot[0] = 1
	if verifier.VerifySubtree(origin, start, end, wrongRoot, sig) {
		t.Error("VerifySubtree succeeded with wrong root")
	}

	if verifier.VerifySubtree("wrong origin", start, end, root, sig) {
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
			timestamp := time.Now().Truncate(time.Second)

			sig, err := signer.SignSubtree(uint64(timestamp.Unix()), origin, start, end, root)
			if err != nil {
				t.Fatalf("SignSubtree: %v", err)
			}

			verifier := signer.Verifier()
			if !verifier.VerifySubtree(origin, start, end, root, sig) {
				t.Fatal("Failed to verify valid subtree signature")
			}
			if gotTimestamp, err := SubtreeTimestamp(sig); err != nil {
				t.Fatalf("Failed to extract timestamp from signature: %v", err)
			} else if gotTimestamp != timestamp {
				t.Fatalf("Signature timestamp %v != expected timestamp %v", gotTimestamp, timestamp)
			}
		})
	}
}

func TestMLDSAVerifyTorchwood(t *testing.T) {
	// Key & Signature generated by filippo.io/torchwood
	vkey := "witness.example/w1+7118e8f9+BhQzSuGTb/4Lcu4MREKut7NjCc8jQ0fjuNpEmJwKF9HV5lt3yF7H5jy+LcLOxjh/n4Gud7NOdRP3KpCH055x6Ntr4n6pZlJ+kmvZTJMgs5ygaJVf6q9zdhykYIPQz4fp6qm0fDXlVBqLVti/3zS0OiY5Kqbi0m55WZ9pnUnsiZT6cckK9FoWfXb1UHTsTgz+Uk+kQr4JHdJ/c5t9V6C0WE8JZMiVT0ljBbfP6VACzuEJmc+zbF8Cbd8Mc31PkTR3YWFok3m4YagXfDlzegsE9jg0qWyTWDDkg+rcrcyCMpPam8LsWxQZXZ2O3w9aDbwKB70URNreL/B6jNl95TXJjtEwmspLPxZwwPI8dE7lJbe9N2X0jQQbpcRvm46iLbZO+LdjblTMHfKgbCqgWej/n3QexrovbetYvrNR2qa7BMJk06PDDy9G8EvtNO6xhVp0DG8z4VkIx+Og9eqk3USAg4bKmN1ifuEeMcnlxvvPwnXjMp6kmmhDEsu1Qu4SgEFOG2PcUKdoaXlIDNADmJQHqeiA+JYhjvyTHDM609qpEkHsRYLbxGidKZtaZptOLEL7sLxIzVQMv07xLw2q9qRFxx3yM8JbhJGg5rP28Xhl+3KcGNXy6Ydxuv3MXYCohjwSqAjOdoxs/FzV10HokFOY60vDQLtMUhby7Ob5VviG6+K5tu6hZogYfme3bzZDLO7VMyHMLKKTjfwJS9p1cagSsbqg5MJucfCfXJAw2vWb8n6eUA6qroBLgY9wjkBg06JAoBv85B7caOBjTitplbXk3pfQAzEE9yKEfSDjEfeVOSrBHK3zJQzw0q8RHSqYs+J7AnFgHxZ5IP5TUWkI/jgg3mdxpbaJ/YJ56uNCgFopQZihOCRVc/RFT53Zb1DXIRgqoP9VTIV3l03VPB2NrH49bEAzsCbNiL4NwLchYxoBZkG4Qp/GpTrjCDoDGtR36JipKbmMforXsz5Oh9Yul8s9p1apJXeSCuGsu5OgRBMXjvUoY9p/GFXHEPd6SPEAtDJfBwC5aWDgl4YC5cxKVzs/+xOvzyXmUg7pxtcJ4vIlWmBrmLb4PGVmPurJwx6BcOp7JRcyHCpycAfGMQ7xsBwafuiVCBQHGJhuDKETJa3MAa4H1uTB7GCiKuT8OohZ2LE/395+sftoy/yrX0H6HdCp+QEQ9ZOx0hbVLBOoAY6qVL1bgEBy/YrHgkCxh2lEWdw+9zb6yLWZI6ONX4mBcj3a5dDYfkvm5gAU4MXGAEWnSNeN9+MkylMQjUM5G2Cn7CTrA7IZ23EZ0bGrRMC7PERKbSj2pITgWqxJWH5l2IyK16cviUaXwGaZg8T8t2p77HtccGUodm6rWS0zBhzEyFajBzSi36b9aa3uDeFjsoEonNUevKg/67jcq5Ua0NWqJ80c5q7glj4wWOMJiDHAFh56UzTPGh1zvndQI4ZxuGHRRgOrTiJ4w3llb9EbsEcTlvFOZzjXrZYfMKTdapHV+5Ykok0+avKNnaOPq9pvtvNDx524IGtQCH9i4RjfefsPsxnloXtqYvoV6O8dCiQHn4jBOECYdqA2ZjYVQ/oPNBt5n5TfNJgLBFokcAKVyrTkWrDXi1OHmw6vEtQJLSv3oqchEYIGXWaEi5/OCtruWfALpEl0rifAMgVhhJp2gL+GZU5c3EGOEwOoQQMKDRdYayEWovpu1KIeOMXaJcDle6hCZEseFxXFDg40MeCdXFyv+Ib55h5uJJDxXdiRzQxdKX+deoY="

	sig := []byte("— witness.example/w1 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\n")

	root, _ := base64.StdEncoding.DecodeString("E7ERCtFloiK1fdb+B6/dLG0pM1nmIR0ETKBSauCjtVw=")

	start, end := uint64(8), uint64(13)
	timestamp := time.Unix(0, 0)
	origin := "example.com/log"

	v, err := NewMLDSAVerifier(vkey)
	if err != nil {
		t.Fatalf("Invalid vkey: %v", err)
	}

	if !v.VerifySubtree(origin, start, end, root, sig) {
		t.Fatal("Failed to verify valid subtree signature")
	}
	if gotTimestamp, err := SubtreeTimestamp(sig); err != nil {
		t.Fatalf("Failed to extract timestamp from signature: %v", err)
	} else if gotTimestamp != timestamp {
		t.Fatalf("Signature timestamp %v != expected timestamp %v", gotTimestamp, timestamp)
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
