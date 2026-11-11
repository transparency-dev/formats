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
	"math"
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
		{
			name: "proof with empty non-nil extra data omits extra line",
			proof: TLogProof{
				Index:      0,
				Hashes:     [][sha256.Size]byte{h1},
				Checkpoint: []byte("checkpoint\n"),
				ExtraData:  []byte{},
			},
			want: fmt.Sprintf("c2sp.org/tlog-proof@v1\nindex 0\n%s\n\ncheckpoint\n", h1b64),
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
			name:          "empty input",
			proof:         []byte(""),
			wantErrSubstr: "missing expected header",
		},
		{
			name:          "header without newline",
			proof:         []byte("c2sp.org/tlog-proof@v1"),
			wantErrSubstr: "missing expected header",
		},
		{
			name:          "truncated after header",
			proof:         []byte("c2sp.org/tlog-proof@v1\n"),
			wantErrSubstr: "missing required index",
		},
		{
			name:          "missing header",
			proof:         []byte("wrong-header\nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "missing expected header",
		},
		{
			name:          "empty extra data",
			proof:         []byte("c2sp.org/tlog-proof@v1\nextra \nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "extra data",
		},
		{
			name:          "extra line without newline",
			proof:         []byte("c2sp.org/tlog-proof@v1\nextra aGVsbG8="),
			wantErrSubstr: "missing required index",
		},
		{
			name:          "truncated after extra line",
			proof:         []byte("c2sp.org/tlog-proof@v1\nextra aGVsbG8=\n"),
			wantErrSubstr: "missing required index",
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
			name:          "index line without newline",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0"),
			wantErrSubstr: "missing required index",
		},
		{
			name:          "invalid index - not a number",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex notanumber\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid",
		},
		{
			name:          "invalid index - negative",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex -5\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid",
		},
		{
			name:          "invalid index - plus sign",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex +1\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid",
		},
		{
			name:          "invalid index - leading zero (00)",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 00\n\ncheckpoint\n"),
			wantErrSubstr: "leading zeros",
		},
		{
			name:          "invalid index - leading zero (007)",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 007\n\ncheckpoint\n"),
			wantErrSubstr: "leading zeros",
		},
		{
			name:          "invalid index - 2^63",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 9223372036854775808\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid",
		},
		{
			name:          "invalid index - MaxUint64",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 18446744073709551615\n\ncheckpoint\n"),
			wantErrSubstr: "not a valid",
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
			// "aGVsbG8=" ("hello") with non-zero padding bits.
			name:          "non-canonical extra data encoding",
			proof:         []byte("c2sp.org/tlog-proof@v1\nextra aGVsbG9=\nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "extra data not base64 encoded",
		},
		{
			// The encoding of 32 zero bytes, with non-zero padding bits.
			name:          "non-canonical hash encoding",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n" + strings.Repeat("A", 42) + "B=\n\ncheckpoint\n"),
			wantErrSubstr: "hash not base64 encoded",
		},
		{
			name:          "oversized hash line (>64 KiB)",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n" + strings.Repeat("a", 65*1024) + "\n\ncheckpoint\n"),
			wantErrSubstr: "hash length",
		},
		{
			name:          "oversized invalid base64 hash line (>64 KiB)",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n" + strings.Repeat("!", 65*1024) + "\n\ncheckpoint\n"),
			wantErrSubstr: "hash not base64 encoded",
		},
		{
			name:          "missing blank line separator after index",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n"),
			wantErrSubstr: "missing blank line",
		},
		{
			name:          "missing blank line separator after hash",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"),
			wantErrSubstr: "missing blank line",
		},
		{
			name:          "hash line without newline",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n" + base64.StdEncoding.EncodeToString(make([]byte, 32))),
			wantErrSubstr: "missing blank line",
		},
		{
			name:          "empty checkpoint after blank line separator",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n\n"),
			wantErrSubstr: "missing checkpoint",
		},
		{
			name:          "empty checkpoint after hashes and blank line separator",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n\n"),
			wantErrSubstr: "missing checkpoint",
		},
		{
			name:          "CRLF on header line",
			proof:         []byte("c2sp.org/tlog-proof@v1\r\nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "carriage return",
		},
		{
			name:          "CRLF on extra line",
			proof:         []byte("c2sp.org/tlog-proof@v1\nextra aGVsbG8=\r\nindex 0\n\ncheckpoint\n"),
			wantErrSubstr: "carriage return",
		},
		{
			name:          "CRLF on index line",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\r\n\ncheckpoint\n"),
			wantErrSubstr: "carriage return",
		},
		{
			name: "CRLF on hash line",
			proof: []byte("c2sp.org/tlog-proof@v1\nindex 0\n" +
				base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\r\n\ncheckpoint\n"),
			wantErrSubstr: "carriage return",
		},
		{
			name:          "CRLF on separator line",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n\r\ncheckpoint\n"),
			wantErrSubstr: "carriage return",
		},
		{
			name:          "CRLF in checkpoint",
			proof:         []byte("c2sp.org/tlog-proof@v1\nindex 0\n\ncheckpoint\r\n"),
			wantErrSubstr: "carriage return",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel := TLogProof{
				Index:      42,
				Hashes:     [][sha256.Size]byte{sha256.Sum256([]byte("sentinel-hash"))},
				Checkpoint: []byte("sentinel-checkpoint\n"),
				ExtraData:  []byte("sentinel-extra"),
			}
			p := TLogProof{
				Index:      sentinel.Index,
				Hashes:     append([][sha256.Size]byte(nil), sentinel.Hashes...),
				Checkpoint: bytes.Clone(sentinel.Checkpoint),
				ExtraData:  bytes.Clone(sentinel.ExtraData),
			}
			err := p.Unmarshal(tt.proof)

			if err == nil {
				t.Fatal("expected error but got none")
			}

			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error message doesn't contain %q, got: %v", tt.wantErrSubstr, err)
			}

			if p.Index != sentinel.Index ||
				len(p.Hashes) != len(sentinel.Hashes) || p.Hashes[0] != sentinel.Hashes[0] ||
				!bytes.Equal(p.Checkpoint, sentinel.Checkpoint) ||
				!bytes.Equal(p.ExtraData, sentinel.ExtraData) {
				t.Errorf("Unmarshal mutated receiver on error: got %+v, want %+v", p, sentinel)
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
			name: "large extra data (>64 KiB)",
			proof: TLogProof{
				Index:      456,
				Hashes:     [][sha256.Size]byte{sha256.Sum256([]byte("c"))},
				Checkpoint: []byte("another checkpoint\n"),
				ExtraData:  bytes.Repeat([]byte("x"), 65*1024),
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
		{
			name: "max index (2^63 - 1)",
			proof: TLogProof{
				Index:      math.MaxInt64,
				Hashes:     nil,
				Checkpoint: []byte("checkpoint\n"),
			},
		},
		{
			name: "multi-signature checkpoint with blank lines",
			proof: TLogProof{
				Index:  73894,
				Hashes: [][sha256.Size]byte{sha256.Sum256([]byte("leaf-sibling"))},
				Checkpoint: []byte("example.com/fancylog\n109482\nsFodV/vSp5O8n9a8QpW6PRY97tfOSW5bsc2Xl/EQi08=\n\n" +
					"— example.com/fancylog hI2DJw1roloI=\n" +
					"— witness1.example mJirIkljqY9v2B/5bg==\n"),
			},
		},
		{
			name: "checkpoint with trailing blank lines",
			proof: TLogProof{
				Index:  1,
				Hashes: nil,
				Checkpoint: []byte("example.com/fancylog\n109482\nsFodV/vSp5O8n9a8QpW6PRY97tfOSW5bsc2Xl/EQi08=\n\n" +
					"— example.com/fancylog hI2DJw1roloI=\n\n\n"),
			},
		},
		{
			name: "checkpoint without trailing newline",
			proof: TLogProof{
				Index:  2,
				Hashes: nil,
				Checkpoint: []byte("example.com/fancylog\n109482\nsFodV/vSp5O8n9a8QpW6PRY97tfOSW5bsc2Xl/EQi08=\n\n" +
					"— example.com/fancylog hI2DJw1roloI="),
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

func TestUnmarshalCheckpointDoesNotAliasInput(t *testing.T) {
	raw := []byte("c2sp.org/tlog-proof@v1\nindex 0\n\nexample.com/log\n1\nhash==\n\n— example.com/log sig==\n")
	p := TLogProof{
		ExtraData: []byte("stale-extra"),
	}
	if err := p.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if p.ExtraData != nil {
		t.Errorf("ExtraData = %q, want nil when extra line is omitted", p.ExtraData)
	}

	wantCP := bytes.Clone(p.Checkpoint)
	// Mutate backing array of raw input.
	for i := range raw {
		raw[i] = 'X'
	}
	if !bytes.Equal(p.Checkpoint, wantCP) {
		t.Errorf("Checkpoint aliased input buffer: got %q, want %q", p.Checkpoint, wantCP)
	}
}

func BenchmarkMarshal(b *testing.B) {
	p := TLogProof{
		Index: 73894,
		Hashes: [][sha256.Size]byte{
			sha256.Sum256([]byte("h1")),
			sha256.Sum256([]byte("h2")),
			sha256.Sum256([]byte("h3")),
			sha256.Sum256([]byte("h4")),
		},
		Checkpoint: []byte("example.com/fancylog\n109482\nsFodV/vSp5O8n9a8QpW6PRY97tfOSW5bsc2Xl/EQi08=\n\n— example.com/fancylog hI2DJw1roloI=\n"),
		ExtraData:  []byte("opaque application context"),
	}
	for b.Loop() {
		_ = p.Marshal()
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	raw := TLogProof{
		Index: 73894,
		Hashes: [][sha256.Size]byte{
			sha256.Sum256([]byte("h1")),
			sha256.Sum256([]byte("h2")),
			sha256.Sum256([]byte("h3")),
			sha256.Sum256([]byte("h4")),
		},
		Checkpoint: []byte("example.com/fancylog\n109482\nsFodV/vSp5O8n9a8QpW6PRY97tfOSW5bsc2Xl/EQi08=\n\n— example.com/fancylog hI2DJw1roloI=\n"),
		ExtraData:  []byte("opaque application context"),
	}.Marshal()

	var p TLogProof
	for b.Loop() {
		if err := p.Unmarshal(raw); err != nil {
			b.Fatal(err)
		}
	}
}
