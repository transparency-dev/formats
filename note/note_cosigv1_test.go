// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

func TestSignerRoundtrip(t *testing.T) {
	skey, _, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSignerForCosignatureV1(skey)
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
			name: "works",
			pubK: "TEST+7997405c+AQcC+FTVKf0jlTdHDY3rbevmnKxxPjigCXlVtGe6RIr6",
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
