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
			want:   "e0b4aa62acca10f5bc40bb803eea643cba17a908bd9cf4e9ef8d736bac47fb48",
		},
		{
			desc:   "usbarmory",
			origin: "Armory Drive Prod 2",
			pk:     []byte("armory-drive-log+16541b8f+AYDPmG5pQp4Bgu0a1mr5uDZ196+t8lIVIfWQSPWmP+Jv"),
			want:   "4ad2fce3c699522bf81ef663bdc973e83a27ea1b8c92ea6d030747d73cd9dae8",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			if got, want := log.ID(test.origin, test.pk), test.want; got != want {
				t.Errorf("got != want (%s != %s)", got, want)
			}
		})
	}
}
