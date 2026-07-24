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

package policy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

const (
	// Plain Ed25519 (0x01) vkeys; usable as log keys but not witness keys.
	wit1_ed25519_vkey = "Wit1+55ee4561+AVhZSmQj9+SoL+p/nN0Hh76xXmF7QcHfytUrI1XfSClk"
	wit1_skey         = "PRIVATE+KEY+Wit1+55ee4561+AeadRiG7XM4XiieCHzD8lxysXMwcViy5nYsoXURWGrlE"
	wit2_ed25519_vkey = "Wit2+85ecc407+AWVbwFJte9wMQIPSnEnj4KibeO6vSIOEDUTDp3o63c2x"
	wit2_skey         = "PRIVATE+KEY+Wit2+85ecc407+AfPTvxw5eUcqSgivo2vaiC7JPOMUZ/9baHPSDrWqgdGm"
	wit3_ed25519_vkey = "Wit3+d3ed3be7+ASb6Uz1+fxAcXkMvDd7nGa3FjDce7LxIKmbbTCT0MpVn"
	wit3_skey         = "PRIVATE+KEY+Wit3+d3ed3be7+AR2Kg8k6ccBr5QXz5SHtnkOS4UGQGEQaWi6Gfr6Mm3X5"

	testOrigin = "example.com/log"
)

var (
	// A plain Ed25519 (0x01) log vkey named after the log's origin.
	log_vkey = genVkey(testOrigin)

	// Witness vkeys must be cosignature key types; these wrap the same
	// Ed25519 public keys as the fixtures above with the 0x04 key type.
	wit1_vkey = rewrapVkey(wit1_ed25519_vkey, 0x04, "Wit1")
	wit2_vkey = rewrapVkey(wit2_ed25519_vkey, 0x04, "Wit2")
	wit3_vkey = rewrapVkey(wit3_ed25519_vkey, 0x04, "Wit3")
	// Further distinct cosignature vkeys, without corresponding signers.
	wit4_vkey = rewrapVkey(genVkey("Wit4"), 0x04, "Wit4")
	wit5_vkey = rewrapVkey(genVkey("Wit5"), 0x04, "Wit5")
	wit6_vkey = rewrapVkey(genVkey("Wit6"), 0x04, "Wit6")

	wit1Sign, _ = f_note.NewSignerForCosignatureV1(wit1_skey)
	wit2Sign, _ = f_note.NewSignerForCosignatureV1(wit2_skey)
	wit3Sign, _ = f_note.NewSignerForCosignatureV1(wit3_skey)

	// ignoreVerifiers excludes the Verifier fields from cmp diffs: the
	// note.Verifier implementations are unexported types with unexported
	// fields, which cmp refuses to compare, and the expected values in
	// test tables carry no verifiers anyway. Tests assert on the
	// verifiers separately where they matter.
	ignoreVerifiers = []cmp.Option{
		cmpopts.IgnoreFields(Log{}, "Verifier"),
		cmpopts.IgnoreFields(Witness{}, "Verifier"),
	}
)

// genVkey returns the vkey of a freshly generated Ed25519 note key pair.
func genVkey(name string) string {
	_, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		panic(fmt.Sprintf("note.GenerateKey(%q): %v", name, err))
	}
	return vkey
}

// rewrapVkey rewraps the public key from vkey with the given algorithm
// octet under the given key name (with a placeholder key id, which
// cosignature verifiers do not validate).
func rewrapVkey(vkey string, alg byte, name string) string {
	key, err := vkeyPublicKey(vkey)
	if err != nil {
		panic(fmt.Sprintf("vkeyPublicKey(%q): %v", vkey, err))
	}
	key[0] = alg
	return fmt.Sprintf("%s+00000000+%s", name, base64.StdEncoding.EncodeToString(key))
}

func TestUnmarshal(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		policy string
		want   TLogPolicy
	}{
		{
			desc: "spec example",
			policy: fmt.Sprintf(`log %s

witness X1 %s
witness X2 %s
witness X3 %s
group X-witnesses 2 X1 X2 X3

witness Y1 %s
witness Y2 %s
witness Y3 %s
group Y-witnesses any Y1 Y2 Y3

group X-and-Y all X-witnesses Y-witnesses
quorum X-and-Y
`, log_vkey, wit1_vkey, wit2_vkey, wit3_vkey, wit4_vkey, wit5_vkey, wit6_vkey),
			want: TLogPolicy{
				Logs: []Log{{VKey: log_vkey}},
				Witnesses: []Witness{
					{Name: "X1", VKey: wit1_vkey},
					{Name: "X2", VKey: wit2_vkey},
					{Name: "X3", VKey: wit3_vkey},
					{Name: "Y1", VKey: wit4_vkey},
					{Name: "Y2", VKey: wit5_vkey},
					{Name: "Y3", VKey: wit6_vkey},
				},
				Groups: []Group{
					{Name: "X-witnesses", Threshold: 2, Members: []string{"X1", "X2", "X3"}},
					{Name: "Y-witnesses", Threshold: 1, Members: []string{"Y1", "Y2", "Y3"}},
					{Name: "X-and-Y", Threshold: 2, Members: []string{"X-witnesses", "Y-witnesses"}},
				},
				Quorum: "X-and-Y",
			},
		},
		{
			desc:   "minimal",
			policy: "quorum none\n",
			want:   TLogPolicy{Quorum: "none"},
		},
		{
			desc: "whitespace and comments",
			policy: "\n# comment\n\t # another comment\n\twitness \t w1  " + wit1_vkey +
				"   https://w1.example.com/  \n\n  quorum\tw1",
			want: TLogPolicy{
				Witnesses: []Witness{{Name: "w1", VKey: wit1_vkey, URL: "https://w1.example.com/"}},
				Quorum:    "w1",
			},
		},
		{
			desc:   "urls optional and opaque",
			policy: fmt.Sprintf("log %s https://log.example.com/\nwitness w1 %s\nquorum w1\n", log_vkey, wit1_vkey),
			want: TLogPolicy{
				Logs:      []Log{{VKey: log_vkey, URL: "https://log.example.com/"}},
				Witnesses: []Witness{{Name: "w1", VKey: wit1_vkey}},
				Quorum:    "w1",
			},
		},
		{
			desc:   "non-ASCII names are opaque octets",
			policy: fmt.Sprintf("witness KKlvin-w\x80 %s\nquorum KKlvin-w\x80\n", wit1_vkey),
			want: TLogPolicy{
				Witnesses: []Witness{{Name: "KKlvin-w\x80", VKey: wit1_vkey}},
				Quorum:    "KKlvin-w\x80",
			},
		},
		{
			desc:   "keywords other than none are valid names",
			policy: fmt.Sprintf("witness all %s\nwitness any %s\ngroup group 2 all any\nquorum group\n", wit1_vkey, wit2_vkey),
			want: TLogPolicy{
				Witnesses: []Witness{
					{Name: "all", VKey: wit1_vkey},
					{Name: "any", VKey: wit2_vkey},
				},
				Groups: []Group{{Name: "group", Threshold: 2, Members: []string{"all", "any"}}},
				Quorum: "group",
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			p := &TLogPolicy{}
			if err := p.Unmarshal([]byte(tc.policy)); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}
			if diff := cmp.Diff(tc.want, *p, ignoreVerifiers...); diff != "" {
				t.Errorf("Unmarshal() diff (-want +got):\n%s", diff)
			}
			for _, l := range p.Logs {
				if l.Verifier == nil {
					t.Errorf("log %q has no verifier", l.VKey)
				}
			}
			for _, w := range p.Witnesses {
				if w.Verifier == nil {
					t.Errorf("witness %q has no verifier", w.Name)
				}
			}
		})
	}
}

func TestUnmarshalMLDSAWitness(t *testing.T) {
	_, vkey, err := f_note.GenerateMLDSAKey("mldsa.example.com")
	if err != nil {
		t.Fatalf("GenerateMLDSAKey() failed: %v", err)
	}
	p := &TLogPolicy{}
	if err := p.Unmarshal(fmt.Appendf(nil, "witness w1 %s\nquorum w1\n", vkey)); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}
	if got, want := p.Witnesses[0].Verifier.Name(), "mldsa.example.com"; got != want {
		t.Errorf("verifier name = %q, want %q", got, want)
	}
}

func TestUnmarshalLogVerifierName(t *testing.T) {
	p := &TLogPolicy{}
	if err := p.Unmarshal(fmt.Appendf(nil, "log %s\nquorum none\n", log_vkey)); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}
	if got, want := p.Logs[0].Verifier.Name(), testOrigin; got != want {
		t.Errorf("log verifier name = %q, want %q", got, want)
	}
}

func TestUnmarshal_Errors(t *testing.T) {
	ecdsaVkey := fmt.Sprintf("ecdsa.example.com+00000000+%s", base64.StdEncoding.EncodeToString([]byte{0x02, 1, 2, 3}))
	// A well-formed vkey with an unknown algorithm octet and a correctly
	// computed key id, which golang.org/x/mod/sumdb/note validates.
	unknownAlgKey := append([]byte{0x63}, make([]byte, 32)...)
	unknownAlgHash := sha256.Sum256([]byte("unknown.example.com\n" + string(unknownAlgKey)))
	unknownAlgVkey := fmt.Sprintf("unknown.example.com+%x+%s", unknownAlgHash[:4], base64.StdEncoding.EncodeToString(unknownAlgKey))
	for _, tc := range []struct {
		desc   string
		policy string
		errStr string
	}{
		{
			desc:   "disallowed control octet",
			policy: "quorum none\n\x01",
			errStr: "invalid octet 0x01",
		},
		{
			desc:   "carriage return",
			policy: "quorum none\r\n",
			errStr: "invalid octet 0x0d",
		},
		{
			desc:   "unknown keyword",
			policy: "quibble w1\nquorum none\n",
			errStr: "unknown keyword",
		},
		{
			desc:   "inline comments are not comments",
			policy: fmt.Sprintf("witness w1 %s https://w1.example.com/ # comment\nquorum w1\n", wit1_vkey),
			errStr: "invalid witness definition",
		},
		{
			desc:   "log without vkey",
			policy: "log\nquorum none\n",
			errStr: "invalid log definition",
		},
		{
			desc:   "log with invalid vkey",
			policy: "log garbage\nquorum none\n",
			errStr: "invalid log vkey",
		},
		{
			desc:   "log with unknown key type",
			policy: fmt.Sprintf("log %s\nquorum none\n", unknownAlgVkey),
			errStr: "unknown verifier algorithm",
		},
		{
			desc:   "duplicate log public key",
			policy: fmt.Sprintf("log %s\nlog %s https://log.example.com/\nquorum none\n", log_vkey, log_vkey),
			errStr: "duplicate log public key",
		},
		{
			desc:   "witness without vkey",
			policy: "witness w1\nquorum none\n",
			errStr: "invalid witness definition",
		},
		{
			desc:   "witness with non-cosignature vkey",
			policy: fmt.Sprintf("witness w1 %s\nquorum w1\n", ecdsaVkey),
			errStr: "key type 0x02 is not a cosignature key type",
		},
		{
			desc:   "witness with plain ed25519 vkey",
			policy: fmt.Sprintf("witness w1 %s\nquorum w1\n", wit1_ed25519_vkey),
			errStr: "key type 0x01 is not a cosignature key type",
		},
		{
			desc:   "witness named none",
			policy: fmt.Sprintf("witness none %s\nquorum none\n", wit1_vkey),
			errStr: "name is reserved",
		},
		{
			desc:   "duplicate witness name",
			policy: fmt.Sprintf("witness w1 %s\nwitness w1 %s\nquorum w1\n", wit1_vkey, wit2_vkey),
			errStr: "duplicate name",
		},
		{
			desc:   "group name duplicates witness name",
			policy: fmt.Sprintf("witness w1 %s\ngroup w1 any w1\nquorum w1\n", wit1_vkey),
			errStr: "duplicate name",
		},
		{
			desc:   "group without members",
			policy: fmt.Sprintf("witness w1 %s\ngroup g1 1\nquorum w1\n", wit1_vkey),
			errStr: "invalid group definition",
		},
		{
			desc:   "group named none",
			policy: fmt.Sprintf("witness w1 %s\ngroup none any w1\nquorum none\n", wit1_vkey),
			errStr: "name is reserved",
		},
		{
			desc:   "zero threshold",
			policy: fmt.Sprintf("witness w1 %s\ngroup g1 0 w1\nquorum g1\n", wit1_vkey),
			errStr: "outside [1, 1]",
		},
		{
			desc:   "negative threshold",
			policy: fmt.Sprintf("witness w1 %s\ngroup g1 -1 w1\nquorum g1\n", wit1_vkey),
			errStr: "invalid threshold",
		},
		{
			desc:   "threshold exceeds members",
			policy: fmt.Sprintf("witness w1 %s\ngroup g1 2 w1\nquorum g1\n", wit1_vkey),
			errStr: "outside [1, 1]",
		},
		{
			desc:   "unknown group member",
			policy: fmt.Sprintf("witness w1 %s\ngroup g1 any w2\nquorum g1\n", wit1_vkey),
			errStr: "unknown member",
		},
		{
			desc:   "forward reference in group",
			policy: fmt.Sprintf("group g1 any w1\nwitness w1 %s\nquorum g1\n", wit1_vkey),
			errStr: "unknown member",
		},
		{
			desc:   "none as group member",
			policy: fmt.Sprintf("witness w1 %s\ngroup g1 any none w1\nquorum g1\n", wit1_vkey),
			errStr: "unknown member",
		},
		{
			desc:   "member repeated within a group",
			policy: fmt.Sprintf("witness w1 %s\ngroup g1 all w1 w1\nquorum g1\n", wit1_vkey),
			errStr: "more than once",
		},
		{
			desc: "member repeated across groups",
			policy: fmt.Sprintf("witness w1 %s\nwitness w2 %s\ngroup g1 any w1 w2\ngroup g2 any w1\nquorum g1\n",
				wit1_vkey, wit2_vkey),
			errStr: "more than once",
		},
		{
			desc:   "no quorum",
			policy: fmt.Sprintf("witness w1 %s\n", wit1_vkey),
			errStr: "exactly one quorum",
		},
		{
			desc:   "multiple quorums",
			policy: fmt.Sprintf("witness w1 %s\nquorum w1\nquorum w1\n", wit1_vkey),
			errStr: "exactly one quorum",
		},
		{
			desc:   "quorum with unknown name",
			policy: "quorum unknown\n",
			errStr: `quorum "unknown" not defined`,
		},
		{
			desc:   "quorum before referenced definition",
			policy: fmt.Sprintf("quorum w1\nwitness w1 %s\n", wit1_vkey),
			errStr: `quorum "w1" not defined`,
		},
		{
			desc:   "quorum without name",
			policy: "quorum\n",
			errStr: "invalid quorum definition",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := (&TLogPolicy{}).Unmarshal([]byte(tc.policy))
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.errStr) {
				t.Errorf("Expected error string to contain %q, got %q", tc.errStr, err.Error())
			}
		})
	}
}

func TestUnmarshal_DuplicateWitnessKeys(t *testing.T) {
	// dup wraps the same public key as wit1_vkey with a different name
	// and key id.
	dup := rewrapVkey(wit1_vkey, 0x04, "impostor.example.com")
	policy := fmt.Sprintf("witness w1 %s\nwitness w2 %s\nquorum w1\n", wit1_vkey, dup)
	err := (&TLogPolicy{}).Unmarshal([]byte(policy))
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if want := "duplicate witness public key"; !strings.Contains(err.Error(), want) {
		t.Errorf("Expected error string to contain %q, got %q", want, err.Error())
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	policy := fmt.Sprintf(`# A policy.
log %s https://log.example.com/
witness w1 %s https://w1.example.com/
witness w2 %s
group g1 any w1 w2
quorum g1
`, log_vkey, wit1_vkey, wit2_vkey)

	p := &TLogPolicy{}
	if err := p.Unmarshal([]byte(policy)); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	marshalled := p.Marshal()
	want := fmt.Sprintf("log %s https://log.example.com/\nwitness w1 %s https://w1.example.com/\nwitness w2 %s\ngroup g1 1 w1 w2\nquorum g1\n",
		log_vkey, wit1_vkey, wit2_vkey)
	if got := string(marshalled); got != want {
		t.Errorf("Marshal() = %q, want %q", got, want)
	}

	p2 := &TLogPolicy{}
	if err := p2.Unmarshal(marshalled); err != nil {
		t.Fatalf("Unmarshal(Marshal()) failed: %v", err)
	}
	if diff := cmp.Diff(*p, *p2, ignoreVerifiers...); diff != "" {
		t.Errorf("policy did not round-trip (-first +second):\n%s", diff)
	}
}

// checkpointBody returns a valid checkpoint body for signing.
func checkpointBody() []byte {
	cp := f_log.Checkpoint{
		Origin: testOrigin,
		Size:   42,
		Hash:   make([]byte, 32),
	}
	return cp.Marshal()
}

// signedCheckpoint returns a checkpoint note signed by the given signers.
func signedCheckpoint(t *testing.T, signers ...note.Signer) []byte {
	t.Helper()
	n := &note.Note{Text: string(checkpointBody())}
	cp, err := note.Sign(n, signers...)
	if err != nil {
		t.Fatalf("note.Sign() failed: %v", err)
	}
	return cp
}

func TestSatisfied(t *testing.T) {
	policy := fmt.Sprintf(`witness w1 %s
witness w2 %s
witness w3 %s
group inner any w2 w3
group outer all w1 inner
quorum outer
`, wit1_vkey, wit2_vkey, wit3_vkey)
	p := &TLogPolicy{}
	if err := p.Unmarshal([]byte(policy)); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	for _, tc := range []struct {
		desc            string
		signers         []note.Signer
		expectSatisfied bool
	}{
		{
			desc:            "all witnesses",
			signers:         []note.Signer{wit1Sign, wit2Sign, wit3Sign},
			expectSatisfied: true,
		},
		{
			desc:            "minimum satisfying set",
			signers:         []note.Signer{wit1Sign, wit3Sign},
			expectSatisfied: true,
		},
		{
			desc:            "outer member without inner group",
			signers:         []note.Signer{wit1Sign},
			expectSatisfied: false,
		},
		{
			desc:            "inner group without outer member",
			signers:         []note.Signer{wit2Sign, wit3Sign},
			expectSatisfied: false,
		},
		{
			desc:            "no cosignatures",
			signers:         []note.Signer{},
			expectSatisfied: false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cp := signedCheckpoint(t, tc.signers...)
			if got, want := p.Satisfied(cp), tc.expectSatisfied; got != want {
				t.Errorf("Satisfied() = %t, want %t", got, want)
			}
		})
	}
}

func TestSatisfiedQuorumNone(t *testing.T) {
	p := &TLogPolicy{}
	if err := p.Unmarshal([]byte("quorum none\n")); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}
	if !p.Satisfied(signedCheckpoint(t)) {
		t.Error("quorum none should always be satisfied")
	}
}

func TestSatisfiedUnknownQuorum(t *testing.T) {
	p := TLogPolicy{Quorum: "missing"}
	if p.Satisfied(signedCheckpoint(t, wit1Sign)) {
		t.Error("a quorum naming an unknown component should never be satisfied")
	}
}

func TestSatisfiedMLDSA(t *testing.T) {
	skey, vkey, err := f_note.GenerateMLDSAKey("mldsa.example.com")
	if err != nil {
		t.Fatalf("GenerateMLDSAKey() failed: %v", err)
	}
	signer, err := f_note.NewMLDSASigner(skey)
	if err != nil {
		t.Fatalf("NewMLDSASigner() failed: %v", err)
	}

	p := &TLogPolicy{}
	if err := p.Unmarshal(fmt.Appendf(nil, "witness w1 %s\nquorum w1\n", vkey)); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}
	if !p.Satisfied(signedCheckpoint(t, signer)) {
		t.Error("expected ML-DSA cosignature to satisfy quorum")
	}
	if p.Satisfied(signedCheckpoint(t)) {
		t.Error("expected unsigned checkpoint not to satisfy quorum")
	}
}

func TestVerify(t *testing.T) {
	logSkey, logVkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatalf("note.GenerateKey() failed: %v", err)
	}
	logSign, err := note.NewSigner(logSkey)
	if err != nil {
		t.Fatalf("note.NewSigner() failed: %v", err)
	}
	otherSkey, otherVkey, err := note.GenerateKey(rand.Reader, "other.example.com/log")
	if err != nil {
		t.Fatalf("note.GenerateKey() failed: %v", err)
	}
	otherSign, err := note.NewSigner(otherSkey)
	if err != nil {
		t.Fatalf("note.NewSigner() failed: %v", err)
	}

	for _, tc := range []struct {
		desc    string
		policy  string
		signers []note.Signer
		errStr  string
	}{
		{
			desc:    "log signature and quorum",
			policy:  fmt.Sprintf("log %s\nwitness w1 %s\nquorum w1\n", logVkey, wit1_vkey),
			signers: []note.Signer{logSign, wit1Sign},
		},
		{
			desc:    "any one of the listed logs suffices",
			policy:  fmt.Sprintf("log %s\nlog %s\nwitness w1 %s\nquorum w1\n", otherVkey, logVkey, wit1_vkey),
			signers: []note.Signer{logSign, wit1Sign},
		},
		{
			desc:    "log signature without quorum",
			policy:  fmt.Sprintf("log %s\nwitness w1 %s\nquorum w1\n", logVkey, wit1_vkey),
			signers: []note.Signer{logSign},
			errStr:  "does not satisfy quorum",
		},
		{
			desc:    "quorum without log signature",
			policy:  fmt.Sprintf("log %s\nwitness w1 %s\nquorum w1\n", logVkey, wit1_vkey),
			signers: []note.Signer{wit1Sign},
			errStr:  "not signed by any log",
		},
		{
			desc:    "log key name must match checkpoint origin",
			policy:  fmt.Sprintf("log %s\nwitness w1 %s\nquorum w1\n", otherVkey, wit1_vkey),
			signers: []note.Signer{otherSign, wit1Sign},
			errStr:  "not signed by any log",
		},
		{
			desc:    "policy without logs",
			policy:  fmt.Sprintf("witness w1 %s\nquorum w1\n", wit1_vkey),
			signers: []note.Signer{logSign, wit1Sign},
			errStr:  "no logs",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			p := &TLogPolicy{}
			if err := p.Unmarshal([]byte(tc.policy)); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}
			cp, err := p.Verify(signedCheckpoint(t, tc.signers...))
			if tc.errStr != "" {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.errStr) {
					t.Errorf("Expected error string to contain %q, got %q", tc.errStr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() failed: %v", err)
			}
			if cp.Origin != testOrigin || cp.Size != 42 {
				t.Errorf("Verify() returned unexpected checkpoint: %+v", cp)
			}
		})
	}
}
