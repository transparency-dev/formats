// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func TestSignerVerifier(t *testing.T) {
	ns, nv, err := note.GenerateKey(nil, "note")
	if err != nil {
		t.Fatalf("note.GenerateKey: %v", err)
	}
	ms, mv, err := GenerateMLDSAKey("mldsa")
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	for _, test := range []struct {
		name string
		s    string
		v    string
	}{
		{name: "note", s: ns, v: nv},
		{name: "mldsa", s: ms, v: mv},
	} {
		t.Run(test.name, func(t *testing.T) {
			ns, err := NewSigner(test.s)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			nv, err := NewVerifier(test.v)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			root := sha256.Sum256([]byte("blah"))
			msg := fmt.Sprintf("%s\n0\n%s\n", test.name, base64.StdEncoding.EncodeToString(root[:]))
			checkRoundTrip(t, msg, ns, nv)
			checkRoundTrip(t, msg, ns, ns.Verifier())
		})
	}
}

func checkRoundTrip(t *testing.T, msg string, s note.Signer, v note.Verifier) {
	t.Helper()
	signed, err := note.Sign(&note.Note{Text: msg}, s)
	if err != nil {
		t.Errorf("%s failed to sign: %v", msg, err)
	}
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("%s failed to open: %v", msg, err)
	}
	if n.Text != msg {
		t.Errorf("got %q want %q", n.Text, msg)
	}
}

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
			checkRoundTrip(t, msg, s, v)
		}
	}
}

func TestNewSignerVerifier_RejectCRLF(t *testing.T) {
	ns, nv, err := note.GenerateKey(nil, "note")
	if err != nil {
		t.Fatalf("note.GenerateKey: %v", err)
	}
	ms, mv, err := GenerateMLDSAKey("mldsa")
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	embedCRLF := func(s string) string {
		return s[:len(s)-4] + "\r\n" + s[len(s)-4:]
	}
	for _, s := range []string{ns + "\r\n", ns + "\r", ns + "\n", embedCRLF(ns), ms + "\r\n", ms + "\r", ms + "\n", embedCRLF(ms)} {
		if _, err := NewSigner(s); err == nil {
			t.Errorf("NewSigner(%q) succeeded, want error", s)
		}
	}
	for _, v := range []string{nv + "\r\n", nv + "\r", nv + "\n", embedCRLF(nv), mv + "\r\n", mv + "\r", mv + "\n", embedCRLF(mv)} {
		if _, err := NewVerifier(v); err == nil {
			t.Errorf("NewVerifier(%q) succeeded, want error", v)
		}
	}
}

func TestNewSignerVerifier_KeyHashValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		skey string
		vkey string
	}{
		{
			name: "mismatched",
			skey: "PRIVATE+KEY+Wit1+00000000+AeadRiG7XM4XiieCHzD8lxysXMwcViy5nYsoXURWGrlE",
			vkey: "PeterNeumann+00000000+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
		},
		{
			name: "non-hex",
			skey: "PRIVATE+KEY+Wit1+zzzzzzzz+AeadRiG7XM4XiieCHzD8lxysXMwcViy5nYsoXURWGrlE",
			vkey: "PeterNeumann+zzzzzzzz+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
		},
		{
			name: "short",
			skey: "PRIVATE+KEY+Wit1+55ee456+AeadRiG7XM4XiieCHzD8lxysXMwcViy5nYsoXURWGrlE",
			vkey: "PeterNeumann+c74f20a+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
		},
		{
			name: "uppercase",
			skey: "PRIVATE+KEY+Wit1+55EE4561+AeadRiG7XM4XiieCHzD8lxysXMwcViy5nYsoXURWGrlE",
			vkey: "PeterNeumann+C74F20A3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSigner(tc.skey); err == nil {
				t.Errorf("NewSigner(%q) succeeded, want error", tc.skey)
			}
			if _, err := NewVerifier(tc.vkey); err == nil {
				t.Errorf("NewVerifier(%q) succeeded, want error", tc.vkey)
			}
		})
	}
}
