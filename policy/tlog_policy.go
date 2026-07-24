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

// Package policy provides support for parsing and evaluating transparency
// log trust policies as described in https://c2sp.org/tlog-policy.
package policy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// quorumNone is the predefined name which, when used as the quorum,
// indicates that no cosignatures are required.
const quorumNone = "none"

const (
	algEd25519CosignatureV1 = 4
	algMLDSA44              = 6
)

// Log represents a log declaration in a policy:
//
//	log <vkey> [<url>]
type Log struct {
	// Verifier verifies this log's checkpoint signatures. Its Name() is the
	// key name from the vkey, which per the spec MUST correspond to the
	// log's origin line.
	Verifier note.Verifier
	// VKey is the log's verifier key exactly as it appeared in the policy.
	VKey string
	// URL is the log's optional application-specific URL, or "" if absent.
	URL string
}

// Witness represents a witness declaration in a policy:
//
//	witness <name> <vkey> [<url>]
type Witness struct {
	// Name identifies this witness within the policy only.
	Name string
	// Verifier verifies this witness' cosignatures.
	Verifier note.Verifier
	// VKey is the witness' verifier key exactly as it appeared in the policy.
	VKey string
	// URL is the witness' optional application-specific URL, or "" if absent.
	URL string
}

// Group represents a group declaration in a policy:
//
//	group <name> <all|any|k> <member>...
type Group struct {
	// Name identifies this group within the policy only.
	Name string
	// Threshold is the number of members which must have witnessed a
	// checkpoint for the group to be considered to have witnessed it.
	// The "any" and "all" keywords are resolved to 1 and len(Members)
	// respectively during parsing, so 1 <= Threshold <= len(Members).
	Threshold int
	// Members are the names of the witnesses and groups this group is
	// composed of. Members always refer to entries defined on earlier
	// lines of the policy.
	Members []string
}

// TLogPolicy represents a transparency log trust policy as described in
// https://c2sp.org/tlog-policy.
type TLogPolicy struct {
	// Logs are the known logs; a checkpoint must be signed by any one of
	// them to be considered valid. May be empty if the applicable log(s)
	// are known from other context.
	Logs []Log
	// Witnesses are the known witnesses, in order of definition.
	Witnesses []Witness
	// Groups are the witness groups, in order of definition.
	Groups []Group
	// Quorum is the name of the witness or group whose witnessing of a
	// checkpoint makes the checkpoint valid, or "none" if no cosignatures
	// are required.
	Quorum string
}

// Unmarshal parses and validates policy text.
//
// The full syntax and structure described by the spec is enforced, e.g.:
// only tab and newline control characters are permitted, comments must be
// whole lines, group members must be defined on earlier lines and may be
// listed as a member at most once, thresholds must be within [1, n], no two
// logs (or witnesses) may share a public key, and exactly one quorum must
// be defined after everything it references.
//
// Witness keys must be tlog-cosignature verifier keys: key types 0x04
// (Ed25519 cosignature/v1) and 0x06 (ML-DSA-44) are supported, and any
// other key type, including plain Ed25519 (0x01), is rejected.
// Log keys may use any note signature algorithm known to the note
// package, since tlog-checkpoint permits logs to use any note signature
// algorithm; unknown key types are rejected.
// Any name except "none" is accepted for witnesses and groups, including
// otherwise-reserved words such as "any"; the grammar is positional so
// such names are unambiguous.
//
// p is only modified if the policy is valid, in which case any previous
// contents are replaced.
func (p *TLogPolicy) Unmarshal(data []byte) error {
	if err := checkCharset(data); err != nil {
		return err
	}

	var out TLogPolicy
	// defined tracks the shared witness/group namespace, mapping each name
	// to true once its definition line has been processed.
	defined := map[string]bool{}
	// member tracks names already listed as a group member; the spec allows
	// each name to be a member at most once across the whole policy.
	member := map[string]bool{}
	logKeys := map[string]bool{}
	witnessKeys := map[string]bool{}
	quorumDefined := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fs := splitFields(scanner.Text())
		if len(fs) == 0 || strings.HasPrefix(fs[0], "#") {
			continue
		}
		line := scanner.Text()
		switch fs[0] {
		case "log":
			if len(fs) < 2 || len(fs) > 3 {
				return fmt.Errorf("invalid log definition: %q", line)
			}
			vkey := fs[1]
			// tlog-checkpoint permits logs to use any note signature
			// algorithm, so accept every key type the note package knows.
			v, err := f_note.NewVerifier(vkey)
			if err != nil {
				return fmt.Errorf("invalid log vkey in %q: %w", line, err)
			}
			key, err := vkeyPublicKey(vkey)
			if err != nil {
				return fmt.Errorf("invalid log vkey in %q: %w", line, err)
			}
			if logKeys[string(key)] {
				return fmt.Errorf("duplicate log public key: %q", vkey)
			}
			logKeys[string(key)] = true
			l := Log{Verifier: v, VKey: vkey}
			if len(fs) == 3 {
				l.URL = fs[2]
			}
			out.Logs = append(out.Logs, l)
		case "witness":
			if len(fs) < 3 || len(fs) > 4 {
				return fmt.Errorf("invalid witness definition: %q", line)
			}
			name, vkey := fs[1], fs[2]
			if name == quorumNone {
				return fmt.Errorf("invalid witness name %q: name is reserved", name)
			}
			if defined[name] {
				return fmt.Errorf("duplicate name: %q", name)
			}
			key, err := vkeyPublicKey(vkey)
			if err != nil {
				return fmt.Errorf("invalid witness vkey in %q: %w", line, err)
			}
			// TODO: remove this check if NewVerifierForCosignatureV1 is
			// changed to reject non-cosignature key types itself.
			if key[0] != algEd25519CosignatureV1 && key[0] != algMLDSA44 {
				return fmt.Errorf("invalid witness vkey in %q: key type 0x%02x is not a cosignature key type", line, key[0])
			}
			v, err := f_note.NewVerifierForCosignatureV1(vkey)
			if err != nil {
				return fmt.Errorf("invalid witness vkey in %q: %w", line, err)
			}
			if witnessKeys[string(key)] {
				return fmt.Errorf("duplicate witness public key: %q", vkey)
			}
			witnessKeys[string(key)] = true
			w := Witness{Name: name, Verifier: v, VKey: vkey}
			if len(fs) == 4 {
				w.URL = fs[3]
			}
			defined[name] = true
			out.Witnesses = append(out.Witnesses, w)
		case "group":
			if len(fs) < 4 {
				return fmt.Errorf("invalid group definition: %q", line)
			}
			name, threshold, members := fs[1], fs[2], fs[3:]
			if name == quorumNone {
				return fmt.Errorf("invalid group name %q: name is reserved", name)
			}
			if defined[name] {
				return fmt.Errorf("duplicate name: %q", name)
			}
			var k int
			switch threshold {
			case "any":
				k = 1
			case "all":
				k = len(members)
			default:
				u, err := strconv.ParseUint(threshold, 10, 31)
				if err != nil {
					return fmt.Errorf("invalid threshold %q for group %q: %w", threshold, name, err)
				}
				k = int(u)
			}
			if k < 1 || k > len(members) {
				return fmt.Errorf("threshold %d for group %q outside [1, %d]", k, name, len(members))
			}
			for _, m := range members {
				if !defined[m] {
					return fmt.Errorf("unknown member %q in group %q", m, name)
				}
				if member[m] {
					return fmt.Errorf("%q cannot be listed as a group member more than once", m)
				}
				member[m] = true
			}
			defined[name] = true
			out.Groups = append(out.Groups, Group{Name: name, Threshold: k, Members: members})
		case "quorum":
			if len(fs) != 2 {
				return fmt.Errorf("invalid quorum definition: %q", line)
			}
			if quorumDefined {
				return fmt.Errorf("policy must include exactly one quorum line")
			}
			quorumDefined = true
			name := fs[1]
			if name != quorumNone && !defined[name] {
				return fmt.Errorf("quorum %q not defined", name)
			}
			out.Quorum = name
		default:
			return fmt.Errorf("unknown keyword: %q", fs[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanning policy: %w", err)
	}
	if !quorumDefined {
		return fmt.Errorf("policy must include exactly one quorum line")
	}

	*p = out
	return nil
}

// Marshal serialises the policy in a canonical form which round-trips
// through Unmarshal. It is not byte-preserving: comments and blank lines
// are not represented, declarations are grouped by type, and thresholds
// are always written numerically.
func (p TLogPolicy) Marshal() []byte {
	var b bytes.Buffer
	for _, l := range p.Logs {
		b.WriteString("log " + l.VKey)
		if l.URL != "" {
			b.WriteString(" " + l.URL)
		}
		b.WriteByte('\n')
	}
	for _, w := range p.Witnesses {
		b.WriteString("witness " + w.Name + " " + w.VKey)
		if w.URL != "" {
			b.WriteString(" " + w.URL)
		}
		b.WriteByte('\n')
	}
	for _, g := range p.Groups {
		fmt.Fprintf(&b, "group %s %d %s\n", g.Name, g.Threshold, strings.Join(g.Members, " "))
	}
	b.WriteString("quorum " + p.Quorum + "\n")
	return b.Bytes()
}

// Satisfied returns true if the checkpoint provided is cosigned by
// witnesses according to the policy's quorum rule.
// This will return false if there are insufficient cosignatures, and also
// if the checkpoint cannot be read as a valid note. It is up to the caller
// to ensure that the input value represents a valid note.
//
// Note that Satisfied does not require a log signature; use Verify to
// apply the policy's full checkpoint validity rule.
func (p TLogPolicy) Satisfied(checkpoint []byte) bool {
	if p.Quorum == quorumNone {
		return true
	}
	witnesses := make(map[string]Witness, len(p.Witnesses))
	for _, w := range p.Witnesses {
		witnesses[w.Name] = w
	}
	groups := make(map[string]Group, len(p.Groups))
	for _, g := range p.Groups {
		groups[g.Name] = g
	}

	visiting := make(map[string]bool)
	var satisfied func(name string) bool
	satisfied = func(name string) bool {
		if w, ok := witnesses[name]; ok {
			n, err := note.Open(checkpoint, note.VerifierList(w.Verifier))
			return err == nil && len(n.Sigs) == 1
		}
		g, ok := groups[name]
		// Unknown names and cyclic references (neither of which can occur
		// in a policy produced by Unmarshal) are never satisfied.
		if !ok || visiting[name] {
			return false
		}
		visiting[name] = true
		defer delete(visiting, name)
		count := 0
		for _, m := range g.Members {
			if satisfied(m) {
				count++
				if count >= g.Threshold {
					return true
				}
			}
		}
		return g.Threshold <= 0
	}
	return satisfied(p.Quorum)
}

// Verify applies the policy's checkpoint validity rule: the provided
// checkpoint must be a note signed by any one of the policy's logs, with
// an origin line matching that log's key name, and it must be cosigned by
// witnesses according to the quorum rule. The parsed checkpoint is
// returned if it is valid.
//
// A policy with an empty set of logs cannot validate any checkpoint; if
// the applicable log is known from other context, verify its signature
// separately and use Satisfied for the quorum rule.
func (p TLogPolicy) Verify(checkpoint []byte) (*f_log.Checkpoint, error) {
	if len(p.Logs) == 0 {
		return nil, fmt.Errorf("policy defines no logs")
	}
	for _, l := range p.Logs {
		cp, _, _, err := f_log.ParseCheckpoint(checkpoint, l.Verifier.Name(), l.Verifier)
		if err != nil {
			continue
		}
		if !p.Satisfied(checkpoint) {
			return nil, fmt.Errorf("checkpoint does not satisfy quorum %q", p.Quorum)
		}
		return cp, nil
	}
	return nil, fmt.Errorf("checkpoint is not signed by any log in the policy")
}

// checkCharset returns an error if data contains an octet not permitted by
// the spec: the only allowed control characters are tab and newline.
func checkCharset(data []byte) error {
	for i, b := range data {
		if b == '\t' || b == '\n' || (b >= 0x20 && b != 0x7f) {
			continue
		}
		return fmt.Errorf("invalid octet 0x%02x at offset %d", b, i)
	}
	return nil
}

// splitFields splits a line into its items. Only space and tab act as
// separators; all other octets, including non-ASCII ones, are opaque data.
func splitFields(line string) []string {
	var fs []string
	start := -1
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' {
			if start >= 0 {
				fs = append(fs, line[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		fs = append(fs, line[start:])
	}
	return fs
}

// vkeyPublicKey returns the decoded key bytes (the algorithm octet
// followed by the public key material) wrapped by a vkey. Two vkeys are
// duplicates if they wrap the same underlying public key, even if they
// differ by key name and key id.
func vkeyPublicKey(vkey string) ([]byte, error) {
	parts := strings.SplitN(vkey, "+", 3)
	if got, want := len(parts), 3; got != want {
		return nil, fmt.Errorf("vkey has %d parts, expected %d", got, want)
	}
	key, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vkey has invalid base64: %v", err)
	}
	if len(key) < 2 {
		return nil, fmt.Errorf("vkey key bytes too short")
	}
	return key, nil
}
