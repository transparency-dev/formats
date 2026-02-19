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
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
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
	if p.ExtraData != nil {
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
	var err error
	b := bufio.NewScanner(bytes.NewReader(data))

	if b.Scan(); b.Text() != tlogProofHeaderV1 {
		return fmt.Errorf("tlog proof missing expected header")
	}

	// Handle optional extra line
	var extra []byte
	if b.Scan(); strings.HasPrefix(b.Text(), "extra ") {
		e, _ := strings.CutPrefix(b.Text(), "extra ")
		extra, err = base64.StdEncoding.DecodeString(e)
		if err != nil {
			return fmt.Errorf("tlog proof extra data not base64 encoded: %w", err)
		}
		b.Scan()
	}

	var idx uint64
	idxStr, ok := strings.CutPrefix(b.Text(), "index ")
	if !ok {
		return fmt.Errorf("tlog proof missing required index")
	}
	idx, err = strconv.ParseUint(idxStr, 10, 64)
	if err != nil {
		return fmt.Errorf("tlog proof index not a valid uint64: %w", err)
	}

	var hashes [][sha256.Size]byte
	for b.Scan() {
		if b.Text() == "" {
			break
		}
		hash, err := base64.StdEncoding.DecodeString(b.Text())
		if err != nil {
			return fmt.Errorf("tlog proof hash not base64 encoded: %w", err)
		}
		if len(hash) != sha256.Size {
			return fmt.Errorf("tlog proof hash length was %d, expected %d", len(hash), sha256.Size)
		}
		hashes = append(hashes, [sha256.Size]byte(hash))
	}

	var checkpoint bytes.Buffer
	for b.Scan() {
		checkpoint.Write(b.Bytes())
		checkpoint.WriteByte('\n')
	}

	if err := b.Err(); err != nil {
		return fmt.Errorf("scanning tlog proof: %w", err)
	}

	p.Index = idx
	p.Hashes = hashes
	p.Checkpoint = checkpoint.Bytes()
	p.ExtraData = extra

	return nil
}
