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
	"strconv"
)

const (
	tlogProofHeaderV1 = "c2sp.org/tlog-proof@v1"
)

// TLogProof represents a transparency log proof as described in https://c2sp.org/tlog-proof
type TLogProof struct {
	// Index is the index of an entry in the log
	Index uint64
	// Hashes is the Merkle inclusion proof as described in https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1.1
	Hashes [][sha256.Size]byte
	// Checkpoint is the signed note as described in https://c2sp.org/tlog-checkpoint
	Checkpoint []byte
	// ExtraData contains optional application-specific data
	ExtraData []byte
}

func (p TLogProof) Marshal() []byte {
	var proof bytes.Buffer
	fmt.Fprintf(&proof, "%s\n", tlogProofHeaderV1)
	if len(p.ExtraData) > 0 {
		proof.WriteString("extra ")
		fmt.Fprintf(&proof, "%s\n", base64.StdEncoding.EncodeToString(p.ExtraData))
	}
	fmt.Fprintf(&proof, "index %d\n", p.Index)
	for _, h := range p.Hashes {
		fmt.Fprintf(&proof, "%s\n", base64.StdEncoding.EncodeToString(h[:]))
	}
	proof.WriteByte('\n')
	proof.Write(p.Checkpoint)
	return proof.Bytes()
}

func (p *TLogProof) Unmarshal(data []byte) error {
	if bytes.IndexByte(data, '\r') >= 0 {
		return fmt.Errorf("tlog proof contains carriage return")
	}

	line, rem, ok := bytes.Cut(data, []byte("\n"))
	if !ok || string(line) != tlogProofHeaderV1 {
		return fmt.Errorf("tlog proof missing expected header")
	}

	line, rem, ok = bytes.Cut(rem, []byte("\n"))
	if !ok {
		return fmt.Errorf("tlog proof missing required index")
	}

	// Handle optional extra line
	var (
		extra []byte
		err   error
	)
	if after, hasExtra := bytes.CutPrefix(line, []byte("extra ")); hasExtra {
		e := string(after)
		if len(e) == 0 {
			return fmt.Errorf("tlog proof empty extra data")
		}
		extra, err = base64.StdEncoding.Strict().DecodeString(e)
		if err != nil {
			return fmt.Errorf("tlog proof extra data not base64 encoded: %w", err)
		}
		line, rem, ok = bytes.Cut(rem, []byte("\n"))
		if !ok {
			return fmt.Errorf("tlog proof missing required index")
		}
	}

	afterIdx, ok := bytes.CutPrefix(line, []byte("index "))
	if !ok {
		return fmt.Errorf("tlog proof missing required index")
	}
	idxStr := string(afterIdx)
	if len(idxStr) > 1 && idxStr[0] == '0' {
		return fmt.Errorf("tlog proof index has leading zeros: %q", idxStr)
	}
	idx, err := strconv.ParseUint(idxStr, 10, 63)
	if err != nil {
		return fmt.Errorf("tlog proof index not a valid int64: %w", err)
	}

	var hashes [][sha256.Size]byte
	for {
		line, rem, ok = bytes.Cut(rem, []byte("\n"))
		if !ok {
			return fmt.Errorf("tlog proof missing blank line before checkpoint")
		}
		if len(line) == 0 {
			break
		}
		hash, err := base64.StdEncoding.Strict().DecodeString(string(line))
		if err != nil {
			return fmt.Errorf("tlog proof hash not base64 encoded: %w", err)
		}
		if len(hash) != sha256.Size {
			return fmt.Errorf("tlog proof hash length was %d, expected %d", len(hash), sha256.Size)
		}
		hashes = append(hashes, [sha256.Size]byte(hash))
	}

	if len(rem) == 0 {
		return fmt.Errorf("tlog proof missing checkpoint")
	}

	p.Index = idx
	p.Hashes = hashes
	p.Checkpoint = bytes.Clone(rem)
	p.ExtraData = extra

	return nil
}
