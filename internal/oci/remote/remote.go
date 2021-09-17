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

package remote

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/internal/oci"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const (
	sigkey    = "dev.cosignproject.cosign/signature"
	certkey   = "dev.sigstore.cosign/certificate"
	chainkey  = "dev.sigstore.cosign/chain"
	BundleKey = "dev.sigstore.cosign/bundle"
)

// This enables mocking for unit testing without faking an entire registry.
var remoteImage = remote.Image

// Signatures fetches the signatures image represented by the named reference.
func Signatures(ref name.Reference, opts ...remote.Option) (oci.Signatures, error) {
	img, err := remoteImage(ref, opts...)
	if err != nil {
		return nil, err
	}
	return &sigs{
		Image: img,
	}, nil
}

type sigs struct {
	v1.Image
}

var _ oci.Signatures = (*sigs)(nil)

// Get implements oci.Signatures
func (s *sigs) Get() ([]oci.Signature, error) {
	m, err := s.Manifest()
	if err != nil {
		return nil, err
	}
	signatures := make([]oci.Signature, 0, len(m.Layers))
	for _, desc := range m.Layers {
		signatures = append(signatures, &sigLayer{
			img:  s,
			desc: desc,
		})
	}
	return signatures, nil
}

type sigLayer struct {
	img  *sigs
	desc v1.Descriptor
}

var _ oci.Signature = (*sigLayer)(nil)

// Payload implements oci.Signature
func (s *sigLayer) Payload() ([]byte, error) {
	l, err := s.img.LayerByDigest(s.desc.Digest)
	if err != nil {
		return nil, err
	}

	// Compressed is a misnomer here, we just want the raw bytes from the registry.
	r, err := l.Compressed()
	if err != nil {
		return nil, err
	}
	payload, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// Base64Signature implements oci.Signature
func (s *sigLayer) Base64Signature() (string, error) {
	b64sig, ok := s.desc.Annotations[sigkey]
	if !ok {
		return "", fmt.Errorf("signature layer %s is missing %q annotation", s.desc.Digest, sigkey)
	}
	return b64sig, nil
}

// Cert implements oci.Signature
func (s *sigLayer) Cert() (*x509.Certificate, error) {
	certPEM, ok := s.desc.Annotations[certkey]
	if !ok {
		return nil, nil
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(certPEM))
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// Chain implements oci.Signature
func (s *sigLayer) Chain() ([]*x509.Certificate, error) {
	chainPEM, ok := s.desc.Annotations[chainkey]
	if !ok {
		return nil, nil
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(chainPEM))
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// Bundle implements oci.Signature
func (s *sigLayer) Bundle() (*oci.Bundle, error) {
	bundle := s.desc.Annotations[BundleKey]
	if bundle == "" {
		return nil, nil
	}
	var b oci.Bundle
	if err := json.Unmarshal([]byte(bundle), &b); err != nil {
		return nil, errors.Wrap(err, "unmarshaling bundle")
	}
	return &b, nil
}
