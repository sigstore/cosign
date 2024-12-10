// Copyright 2023 The Sigstore Authors.
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

package attest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func predicateReader(predicatePath string) (io.ReadCloser, error) {
	if predicatePath == "-" {
		fmt.Fprintln(os.Stderr, "Using payload from: standard input")
		return os.Stdin, nil
	}

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
	f, err := os.Open(predicatePath)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func getEnvelopeSigBytes(envelopeBytes []byte) ([]byte, error) {
	var envelope dsse.Envelope
	err := json.Unmarshal(envelopeBytes, &envelope)
	if err != nil {
		return nil, err
	}
	if len(envelope.Signatures) == 0 {
		return nil, fmt.Errorf("envelope has no signatures")
	}
	return base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
}
