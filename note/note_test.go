// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"fmt"
	"testing"
	"golang.org/x/mod/sumdb/note"
)

func TestNoteInterop(t *testing.T) {
	sk, vk, err := note.GenerateKey(nil, "example")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sf, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner(%q): %v", sk, err)
	}
	vf, err := NewVerifier(vk)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	sn, err := note.NewSigner(sk)
	if err != nil {
		t.Fatalf("note.NewSigner: %v", err)
	}
	vn, err := note.NewVerifier(vk)
	if err != nil {
		t.Fatalf("note.NewVerifier: %v", err)
	}

	for i, s := range []note.Signer{sf, sn} {
		for j, v := range []note.Verifier{vf, vn} {
			msg := fmt.Sprintf("%d, %d\n", i, j)
			signed, err := note.Sign(&note.Note{Text: msg}, s)
			if err != nil {
				t.Errorf("%s failed to sign: %v", msg, err)
				continue
			}

			n, err := note.Open(signed, note.VerifierList(v))
			if err != nil {
				t.Errorf("%s failed to open: %v", msg, err)
				continue
			}

			if n.Text != msg {
				t.Errorf("got %q want %q", n.Text, msg)
			}
		}
	}
}
