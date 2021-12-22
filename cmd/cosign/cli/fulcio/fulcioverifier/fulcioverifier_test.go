//
// Copyright 2021 The Sigstore Authors.
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

package fulcioverifier

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestGetAlternatePublicKey(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get cwd: %v", err)
	}
	tests := []struct {
		file       string
		wantErrSub string
		wantType   string
	}{
		{file: "garbage-there-are-limits", wantErrSub: "failed to parse"},
		// Testflume 2021 from here, https://letsencrypt.org/docs/ct-logs/
		{file: "letsencrypt-testflume-2021", wantType: "*ecdsa.PublicKey"},
		// This needs to be parsed with the pkcs1, pkix won't do.
		{file: "rsa", wantType: "*rsa.PublicKey"},
		// This works with pkix, from:
		// https://www.gstatic.com/ct/log_list/v2/log_list_pubkey.pem
		{file: "google", wantType: "*rsa.PublicKey"},
	}
	for _, tc := range tests {
		filepath := fmt.Sprintf("%s/testdata/%s", wd, tc.file)
		bytes, err := ioutil.ReadFile(filepath)
		if err != nil {
			t.Fatalf("Failed to read testfile %s : %v", tc.file, err)
		}
		got, err := getAlternatePublicKey(bytes)
		switch {
		case err == nil && tc.wantErrSub != "":
			t.Errorf("Wanted Error for %s but got none", tc.file)
		case err != nil && tc.wantErrSub == "":
			t.Errorf("Did not want error for %s but got: %v", tc.file, err)
		case err != nil && tc.wantErrSub != "":
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("Unexpected error for %s: %s wanted to contain: %s", tc.file, err.Error(), tc.wantErrSub)
			}
		}
		switch {
		case got == nil && tc.wantType != "":
			t.Errorf("Wanted public key for %s but got none", tc.file)
		case got != nil && tc.wantType == "":
			t.Errorf("Did not want error for %s but got: %v", tc.file, err)
		case got != nil && tc.wantType != "":
			if reflect.TypeOf(got).String() != tc.wantType {
				t.Errorf("Unexpected type for %s: %+T wanted: %s", tc.file, got, tc.wantType)
			}
		}
	}
}
