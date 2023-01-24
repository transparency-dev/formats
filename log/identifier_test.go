// Copyright 2021 Google LLC. All Rights Reserved.
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

package log_test

import (
	"testing"

	"github.com/transparency-dev/formats/log"
)

func TestID(t *testing.T) {
	for _, test := range []struct {
		desc   string
		origin string
		pk     []byte
		want   string
	}{
		{
			desc:   "sumdb",
			origin: "go.sum database tree",
			pk:     []byte("sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"),
			want:   "bdc0d5078d38fc2b9491df373eb7c0d3365bfe661c83edc89112fd38719dc3a0",
		},
		{
			desc:   "usbarmory",
			origin: "Armory Drive Prod 2",
			pk:     []byte("armory-drive-log+16541b8f+AYDPmG5pQp4Bgu0a1mr5uDZ196+t8lIVIfWQSPWmP+Jv"),
			want:   "a49f0a631f86d3e4fc6726e4389d1cc1998731aa58be95e3e81026d35d2b2902",
		},
		{
			desc:   "rekor 1",
			origin: "rekor.sigstore.dev - 2605736670972794746",
			pk:     []byte("rekor.sigstore.dev+c0d23d6a+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNhtmPtrWm3U1eQXBogSMdGvXwBcK5AW5i0hrZLOC96l+smGNM7nwZ4QvFK/4sueRoVj//QP22Ni4Qt9DPfkWLc="),
			want:   "50ed07082843287df5342353a4084563e6eaeb7bbaaa961d45400dde004c1186",
		},
		{
			desc:   "rekor 2",
			origin: "rekor.sigstore.dev - 3904496407287907110",
			pk:     []byte("rekor.sigstore.dev+c0d23d6a+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNhtmPtrWm3U1eQXBogSMdGvXwBcK5AW5i0hrZLOC96l+smGNM7nwZ4QvFK/4sueRoVj//QP22Ni4Qt9DPfkWLc="),
			want:   "9b2bc13a3839d8a954832caa002ce8d7fb3d0bf7f4ce4a310a7dbbf28de101a8",
		},
		{
			desc:   "rekor 3",
			origin: "rekor.sigstore.dev - 3904496407287907110",
			pk:     []byte("armory-drive-log+16541b8f+AYDPmG5pQp4Bgu0a1mr5uDZ196+t8lIVIfWQSPWmP+Jv"),
			want:   "27ad43bd0470950078c0aeb4bd7293d8dc6e47cb969f18aa958f1db6dd27b337",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			if got, want := log.ID(test.origin, test.pk), test.want; got != want {
				t.Errorf("got != want (%s != %s)", got, want)
			}
		})
	}
}
