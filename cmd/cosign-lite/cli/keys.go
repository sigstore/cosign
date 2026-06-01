// Copyright 2026 The Sigstore Authors.
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

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
)

func generateKeyPair(prefix string, passFunc func(bool) ([]byte, error)) error {
	privateKeyPath := prefix + ".key"
	publicKeyPath := prefix + ".pub"

	if _, err := os.Stat(privateKeyPath); err == nil {
		return fmt.Errorf("file %s already exists; generation halted to prevent accidental overwrite", privateKeyPath)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	var pass []byte
	if passFunc != nil {
		pass, err = passFunc(true)
		if err != nil {
			return fmt.Errorf("getting password: %w", err)
		}
	}

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}

	encryptedBytes, err := encrypted.Encrypt(x509Encoded, pass)
	if err != nil {
		return fmt.Errorf("encrypting private key: %w", err)
	}

	privBlock := &pem.Block{
		Type:  "ENCRYPTED SIGSTORE PRIVATE KEY",
		Bytes: encryptedBytes,
	}
	privPEMBytes := pem.EncodeToMemory(privBlock)
	if err := os.WriteFile(privateKeyPath, privPEMBytes, 0600); err != nil {
		return fmt.Errorf("writing private key file: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pubPEMBytes := pem.EncodeToMemory(pubBlock)
	if err := os.WriteFile(publicKeyPath, pubPEMBytes, 0644); err != nil { //nolint: gosec
		return fmt.Errorf("writing public key file: %w", err)
	}

	return nil
}

func getPass(confirm bool) ([]byte, error) {
	pw, ok := env.LookupEnv(env.VariablePassword)
	switch {
	case ok:
		return []byte(pw), nil
	case cosign.IsTerminal():
		return cosign.GetPassFromTerm(confirm)
	default:
		return io.ReadAll(os.Stdin)
	}
}
