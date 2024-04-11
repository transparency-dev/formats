// Copyright 2024 Google LLC. All Rights Reserved.
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

package note

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

const (
	romeCP    = "rome.ct.filippo.io/2024h1\n115474666\n2q1K6aiIJR+F7TyhiWOghoWOjY0/3dVBLsBbAvB4xCw=\n\n— rome.ct.filippo.io/2024h1 ePSrrgAAAY5+gVlSBAMARzBFAiEAv8bOMzo3Ed/GbU9fzzJvaStX6i8xTsmEF+NqvpGhIO0CIEn1X+zzVEerdix64GEn97XCXObA2G5JQ8UDDqCKdG5m\n"
	romeURL   = "https://rome.ct.filippo.io/2024h1/"
	romePKDER = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAXM8Ld9qn64g1zVFDh5FtgxS3zj5sqQDwYMs3wrBV3MCBiFhK/iRLxdKF4YsAcJaEglMlu4Lewvzxs0xO2uwEw=="
)

func TestRFC6962VerifierString(t *testing.T) {
	for _, test := range []struct {
		name    string
		url     string
		pubK    []byte
		want    string
		wantErr bool
	}{
		{
			name: "works - argon ECDSA",
			url:  "https://ct.googleapis.com/logs/us1/argon2024/",
			pubK: mustB64(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="),
			want: "ct.googleapis.com/logs/us1/argon2024+7deb49d0+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB25bKnLaZTFXOa2pgO70rjcVEMXKJkMBgFQHZ1kwFlGK9zIAx0FtC2oCfeZQe0E++VXuiYE9hFSzhRlOy92K8A=",
		}, {
			name: "works - rome ECDSA",
			url:  romeURL,
			pubK: mustB64(t, romePKDER),
			want: "rome.ct.filippo.io/2024h1+78f4abae+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAFzPC3fap+uINc1RQ4eRbYMUt84+bKkA8GDLN8KwVdzAgYhYSv4kS8XSheGLAHCWhIJTJbuC3sL88bNMTtrsBM=",
		}, {
			name: "works - no scheme",
			url:  "ct.googleapis.com/logs/us1/argon2024/",
			pubK: mustB64(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="),
			want: "ct.googleapis.com/logs/us1/argon2024+7deb49d0+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB25bKnLaZTFXOa2pgO70rjcVEMXKJkMBgFQHZ1kwFlGK9zIAx0FtC2oCfeZQe0E++VXuiYE9hFSzhRlOy92K8A=",
		}, {
			name: "works - no trailing slash",
			url:  "ct.googleapis.com/logs/us1/argon2024",
			pubK: mustB64(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="),
			want: "ct.googleapis.com/logs/us1/argon2024+7deb49d0+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB25bKnLaZTFXOa2pgO70rjcVEMXKJkMBgFQHZ1kwFlGK9zIAx0FtC2oCfeZQe0E++VXuiYE9hFSzhRlOy92K8A=",
		}, {
			name:    "invalid name",
			url:     "ct.googleapis.com/logs/us1/argon2024+cheese",
			pubK:    mustB64(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="),
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			k, err := x509.ParsePKIXPublicKey(test.pubK)
			if err != nil {
				t.Fatalf("Bad test data, couldn't parse key: %v", err)
			}
			got, err := RFC6962VerifierString(test.url, k)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("Got err %v, but wantErr: %T", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("Got %q, want %q", got, test.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	for _, test := range []struct {
		name     string
		cp       []byte
		verifier string
		wantErr  bool
	}{
		{
			name:     "works - rome",
			cp:       []byte(romeCP),
			verifier: "rome.ct.filippo.io/2024h1+78f4abae+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAFzPC3fap+uINc1RQ4eRbYMUt84+bKkA8GDLN8KwVdzAgYhYSv4kS8XSheGLAHCWhIJTJbuC3sL88bNMTtrsBM=",
		}, {
			name:     "invalid signature",
			cp:       []byte("B0rked" + romeCP),
			verifier: "rome.ct.filippo.io/2024h1+78f4abae+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAFzPC3fap+uINc1RQ4eRbYMUt84+bKkA8GDLN8KwVdzAgYhYSv4kS8XSheGLAHCWhIJTJbuC3sL88bNMTtrsBM=",
			wantErr:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, err := NewRFC6962Verifier(test.verifier)
			if err != nil {
				t.Fatalf("Invalid verifier: %v", err)
			}

			n, err := note.Open(test.cp, note.VerifierList(v))
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("Got err %q, want err %t", err, test.wantErr)
			}

			t.Logf("%v", n)
		})
	}
}

func TestRFC6962ToNote(t *testing.T) {
	for _, test := range []struct {
		name     string
		sth      []byte
		verifier string
		wantErr  bool
	}{
		{
			name:     "works",
			sth:      []byte(`{"tree_size":1267285836,"timestamp":1711642477482,"sha256_root_hash":"SHySaYoaGIV5oCMANTytRfUjfzXb7wvO9xQiGkDJlfQ=","tree_head_signature":"BAMARzBFAiAQWbsL/MbJdeR4jk8xYKWDBDGHyDcntBim9Jr1BvwPnAIhAMedQo0YuBo+ajNd9xyVOMvhOdVAeJYgOhBLQn8rca94"}`),
			verifier: "ct.googleapis.com/logs/us1/argon2024+7deb49d0+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB25bKnLaZTFXOa2pgO70rjcVEMXKJkMBgFQHZ1kwFlGK9zIAx0FtC2oCfeZQe0E++VXuiYE9hFSzhRlOy92K8A=",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, err := NewRFC6962Verifier(test.verifier)
			if err != nil {
				t.Fatalf("Invalid verifier: %v", err)
			}

			nRaw, err := RFC6962STHToCheckpoint(test.sth, v)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("Got err %q, wantErr: %t", err, test.wantErr)
			}
			n, err := note.Open(nRaw, note.VerifierList(v))
			if err != nil {
				t.Fatalf("Failed to open note: %v", err)
			}

			var sth signedTreeHead
			if err := json.Unmarshal(test.sth, &sth); err != nil {
				t.Fatalf("Failed to parse STH json: %v", err)
			}

			lines := strings.Split(n.Text, "\n")
			if got, want := lines[0], v.Name(); got != want {
				t.Errorf("Got origin %q, want %q", got, want)
			}
			if got, want := lines[1], strconv.FormatUint(sth.TreeSize, 10); got != want {
				t.Errorf("Got treesize %q, want %q", got, want)
			}
			if got, want := lines[2], base64.StdEncoding.EncodeToString(sth.SHA256RootHash); got != want {
				t.Errorf("Got roothash %q, want %q", got, want)
			}
		})
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}
	return b
}
