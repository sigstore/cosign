// Copyright 2022 The Sigstore Authors.
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

package protobundle

import (
	"fmt"

	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbrekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// GenerateTransparencyLogEntry returns a sigstore/protobuf-specs compliant message containing a
// TransparencyLogEntry as defined at https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_rekor.proto
func GenerateTransparencyLogEntry(anon models.LogEntryAnon) (*pbrekor.TransparencyLogEntry, error) {
	return tle.GenerateTransparencyLogEntry(anon)
}

// GenerateX509CertificateChain returns a sigstore/protobuf-specs compliant message containing a
// X509CertificateChain as defined at https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_common.proto
func GenerateX509CertificateChain(pemBytes []byte) (*pbcommon.X509CertificateChain, error) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("error getting cert: %w", err)
	}
	chain := []*pbcommon.X509Certificate{}
	for _, cert := range certs {
		chain = append(chain, &pbcommon.X509Certificate{RawBytes: cert.Raw})
	}
	return &pbcommon.X509CertificateChain{Certificates: chain}, nil
}
