//go:build !pivkey || !cgo
// +build !pivkey !cgo

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

package pivkey

import (
	"crypto/x509"
	"errors"

	"github.com/sigstore/sigstore/pkg/signature"
)

// The empty struct is used so this file never imports piv-go which is
// dependent on cgo and will fail to build if imported.
type empty struct{} //nolint

type Key struct{}

func GetKey() (*Key, error) {
	return nil, errors.New("unimplemented")
}

func GetKeyWithSlot(slot string) (*Key, error) {
	return nil, errors.New("unimplemented")
}

func (k *Key) Close() {}

func (k *Key) Authenticate(pin string) {}

func (k *Key) SetSlot(slot string) {}

func (k *Key) Attest() (*x509.Certificate, error) {
	return nil, errors.New("unimplemented")
}

func (k *Key) GetAttestationCertificate() (*x509.Certificate, error) {
	return nil, errors.New("unimplemented")
}

func (k *Key) SetManagementKey(old, new [24]byte) error {
	return errors.New("unimplemented")
}

func (k *Key) SetPIN(old, new string) error {
	return errors.New("unimplemented")
}

func (k *Key) SetPUK(old, new string) error {
	return errors.New("unimplemented")
}

func (k *Key) Reset() error {
	return errors.New("unimplemented")
}

func (k *Key) Unblock(puk, newPIN string) error {
	return errors.New("unimplemented")
}

func (k *Key) GenerateKey(mgmtKey [24]byte, slot *empty, opts *empty) (*empty, error) { //nolint
	return nil, errors.New("unimplemented")
}

func (k *Key) Verifier() (signature.Verifier, error) {
	return nil, errors.New("unimplemented")
}

func (k *Key) Certificate() (*x509.Certificate, error) {
	return nil, errors.New("unimplemented")
}

func (k *Key) SignerVerifier() (signature.SignerVerifier, error) {
	return nil, errors.New("unimplemented")
}
