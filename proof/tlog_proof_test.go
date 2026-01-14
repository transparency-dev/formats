// Copyright 2026 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestMarshal(t *testing.T) {
	h1 := sha256.Sum256([]byte("hash1"))
	h2 := sha256.Sum256([]byte("hash2"))
	h1b64 := base64.StdEncoding.EncodeToString(h1[:])
	h2b64 := base64.StdEncoding.EncodeToString(h2[:])
	extra := []byte("extra information")
	extraB64 := base64.StdEncoding.EncodeToString(extra)

	tests := []struct {
		name  string
		proof TLogProof
		want  string
	}{
		{
			name: "proof without extra data",
			proof: TLogProof{
				Index:      5,
				Hashes:     [][sha256.Size]byte{h1, h2},
				Checkpoint: []byte("test checkpoint\n"),
			},
			want: fmt.Sprintf("c2sp.org/tlog-proof@v1\nindex 5\n%s\n%s\n\ntest checkpoint\n", h1b64, h2b64),
		},
		{
			name: "proof with extra data",
			proof: TLogProof{
				Index:      10,
				Hashes:     [][sha256.Size]byte{h1},
				Checkpoint: []byte("checkpoint data\n"),
				ExtraData:  extra,
			},
			want: fmt.Sprintf("c2sp.org/tlog-proof@v1\nextra %s\nindex 10\n%s\n\ncheckpoint data\n", extraB64, h1b64),
		},
		{
			name: "proof with empty hashes",
			proof: TLogProof{
				Index:      0,
				Hashes:     [][sha256.Size]byte{},
				Checkpoint: []byte("checkpoint\n"),
			},
			want: "c2sp.org/tlog-proof@v1\nindex 0\n\ncheckpoint\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.proof.Marshal()); got != tt.want {
				t.Errorf("Marshal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name          string
		proof         []byte
		wantErrSubstr string
	}{
		{
			name:          "missing header",
			proof:         []byte("wrong-header\nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "missing expected header",
		},
		{
			name:          "invalid extra data encoding",
			proof:         []byte("c2sp.org/tlog-proof@v1\nextra !!notbase64!!\nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "extra data not base64 encoded",
		},
		{
			name:          "missing index",
			proof:         []byte("c2sp.org/tlog-proof@v1\n\n\ncheckpoint\n"),
			wantErrSubstr: "missing required index",
		},
		{
			name:          "invalid index - not a number",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex notanumber\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid uint64",
		},
		{
			name:          "invalid index - negative",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex -5\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid uint64",
		},
		{
			name:          "invalid hash base64",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n!!notbase64!!\n\ncheckpoint\n"),
			wantErrSubstr: "hash not base64 encoded",
		},
		{
			name: "incorrect hash length",
			proof: []byte("c2sp.org/tlog-proof@v1\nindex 0\n" +
				base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n\ncheckpoint\n"),
			wantErrSubstr: "hash length",
		},
		{
			name:          "scanner error - buffer too large",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n" + strings.Repeat("a", 65*1024) + "\n"),
			wantErrSubstr: "scanning tlog proof",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p TLogProof
			err := p.Unmarshal(tt.proof)

			if err == nil {
				t.Fatal("expected error but got none")
			}

			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error message doesn't contain %q, got: %v", tt.wantErrSubstr, err)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		proof TLogProof
	}{
		{
			name: "simple proof",
			proof: TLogProof{
				Index:      123,
				Hashes:     [][sha256.Size]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))},
				Checkpoint: []byte("some checkpoint\n"),
			},
		},
		{
			name: "proof with extra data",
			proof: TLogProof{
				Index:      456,
				Hashes:     [][sha256.Size]byte{sha256.Sum256([]byte("c"))},
				Checkpoint: []byte("another checkpoint\n"),
				ExtraData:  []byte("some extra data"),
			},
		},
		{
			name: "empty hashes",
			proof: TLogProof{
				Index:      789,
				Hashes:     nil,
				Checkpoint: []byte("checkpoint\n"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marshaled := tt.proof.Marshal()

			var unmarshaled TLogProof
			if err := unmarshaled.Unmarshal(marshaled); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if unmarshaled.Index != tt.proof.Index {
				t.Errorf("Index mismatch: got %d, want %d", unmarshaled.Index, tt.proof.Index)
			}
			if !bytes.Equal(unmarshaled.Checkpoint, tt.proof.Checkpoint) {
				t.Errorf("Checkpoint mismatch: got %q, want %q", unmarshaled.Checkpoint, tt.proof.Checkpoint)
			}
			if !bytes.Equal(unmarshaled.ExtraData, tt.proof.ExtraData) {
				t.Errorf("ExtraData mismatch: got %q, want %q", unmarshaled.ExtraData, tt.proof.ExtraData)
			}
			if len(unmarshaled.Hashes) != len(tt.proof.Hashes) {
				t.Errorf("Hashes length mismatch: got %d, want %d", len(unmarshaled.Hashes), len(tt.proof.Hashes))
			}
			for i := range unmarshaled.Hashes {
				if unmarshaled.Hashes[i] != tt.proof.Hashes[i] {
					t.Errorf("Hash %d mismatch", i)
				}
			}
		})
	}
}
