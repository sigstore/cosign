// +build pivkey
// +build cgo

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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/term"
)

func GetKey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no cards found")
	}
	if len(cards) > 1 {
		return nil, fmt.Errorf("found %d cards, please attach only one", len(cards))
	}
	yk, err := piv.Open(cards[0])
	if err != nil {
		return nil, err
	}
	return yk, nil
}

func getPin() (string, error) {
	fmt.Fprint(os.Stderr, "Enter PIN for security key: ")
	b, err := term.ReadPassword(0)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr, "\nPlease tap security key...")
	return string(b), err
}

func NewPublicKeyProvider(slotName string) (signature.Verifier, error) {
	pk, err := GetKey()
	if err != nil {
		return nil, err
	}

	slot := SlotForName(slotName)
	if slot == nil {
		return nil, errors.New("invalid slot name")
	}

	cert, err := pk.Attest(*slot)
	if err != nil {
		return nil, err
	}
	ev, err := signature.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &PIVSignerVerifier{
		Pub:           cert.PublicKey,
		ECDSAVerifier: ev,
	}, nil
}

func NewSignerVerifier(slotName string) (signature.SignerVerifier, error) {
	pk, err := GetKey()
	if err != nil {
		return nil, err
	}

	slot := SlotForName(slotName)
	if slot == nil {
		return nil, errors.New("invalid slot name")
	}

	cert, err := pk.Attest(*slot)
	if err != nil {
		return nil, err
	}

	auth := piv.KeyAuth{
		PINPrompt: getPin,
	}
	privKey, err := pk.PrivateKey(*slot, cert.PublicKey, auth)
	if err != nil {
		return nil, err
	}
	ev, err := signature.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &PIVSignerVerifier{
		Priv:          privKey,
		Pub:           cert.PublicKey,
		ECDSAVerifier: ev,
	}, nil
}

type PIVSignerVerifier struct {
	Priv crypto.PrivateKey
	Pub  crypto.PrivateKey
	*signature.ECDSAVerifier
}

func (ps *PIVSignerVerifier) Sign(ctx context.Context, rawPayload []byte) ([]byte, []byte, error) {
	signer := ps.Priv.(crypto.Signer)
	h := sha256.Sum256(rawPayload)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return sig, h[:], err
}

func (ps *PIVSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	signer := ps.Priv.(crypto.Signer)

	h := sha256.New()
	if _, err := io.Copy(h, message); err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return sig, err
}

func (ps *PIVSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return ps.Pub, nil
}

var _ signature.Signer = &PIVSignerVerifier{}

func GetYubikey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return nil, err
			}
			return yk, nil
		}
	}
	return nil, errors.New("no yubikey found")
}

func GenYubikey(yk *piv.YubiKey) (crypto.PublicKey, error) {
	// Generate a private key on the YubiKey.
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	pub, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
