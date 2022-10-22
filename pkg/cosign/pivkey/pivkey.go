//go:build pivkey && cgo
// +build pivkey,cgo

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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/term"

	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	KeyNotInitialized error = errors.New("key not initialized")
	SlotNotSet        error = errors.New("slot not set")
)

type Key struct {
	Pub  crypto.PublicKey
	Priv crypto.PrivateKey

	card *piv.YubiKey
	slot *piv.Slot
	pin  string
}

func GetKey() (*Key, error) {
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
	return &Key{card: yk}, nil
}

func GetKeyWithSlot(slot string) (*Key, error) {
	card, err := GetKey()
	if err != nil {
		return nil, fmt.Errorf("open key: %w", err)
	}

	card.slot = SlotForName(slot)

	return card, nil
}

func (k *Key) Close() {
	k.Pub = nil
	k.Priv = nil

	k.slot = nil
	k.pin = ""
	k.card.Close()
}

func (k *Key) Authenticate(pin string) {
	k.pin = pin
}

func (k *Key) SetSlot(slot string) {
	k.slot = SlotForName(slot)
}

func (k *Key) Attest() (*x509.Certificate, error) {
	if k.card == nil {
		return nil, KeyNotInitialized
	}

	return k.card.Attest(*k.slot)
}

func (k *Key) GetAttestationCertificate() (*x509.Certificate, error) {
	if k.card == nil {
		return nil, KeyNotInitialized
	}

	return k.card.AttestationCertificate()
}

func (k *Key) SetManagementKey(old, new [24]byte) error {
	if k.card == nil {
		return KeyNotInitialized
	}

	return k.card.SetManagementKey(old, new)
}

func (k *Key) SetPIN(old, new string) error {
	if k.card == nil {
		return KeyNotInitialized
	}

	return k.card.SetPIN(old, new)
}

func (k *Key) SetPUK(old, new string) error {
	if k.card == nil {
		return KeyNotInitialized
	}

	return k.card.SetPUK(old, new)
}

func (k *Key) Reset() error {
	if k.card == nil {
		return KeyNotInitialized
	}

	return k.card.Reset()
}

func (k *Key) Unblock(puk, newPIN string) error {
	if k.card == nil {
		return KeyNotInitialized
	}

	return k.card.Unblock(puk, newPIN)
}

func (k *Key) GenerateKey(mgmtKey [24]byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if k.card == nil {
		return nil, KeyNotInitialized
	}

	return k.card.GenerateKey(mgmtKey, slot, opts)
}

func (k *Key) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return k.Pub, nil
}

func (k *Key) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	sig, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	msg, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}
	digest := sha256.Sum256(msg)

	att, err := k.Attest()
	if err != nil {
		return fmt.Errorf("get attestation: %w", err)
	}
	switch kt := att.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(kt, digest[:], sig) {
			return nil
		}
		return errors.New("invalid ecdsa signature")
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(kt, crypto.SHA256, digest[:], sig)
	}

	return fmt.Errorf("unsupported key type: %T", att.PublicKey)
}

func getPin() (string, error) {
	fmt.Fprint(os.Stderr, "Enter PIN for security key: ")
	// Unnecessary convert of syscall.Stdin on *nix, but Windows is a uintptr
	// nolint:unconvert
	b, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr, "\nPlease tap security key...")
	return string(b), err
}

func (k *Key) Verifier() (signature.Verifier, error) {
	if k.card == nil {
		return nil, KeyNotInitialized
	}
	if k.slot == nil {
		return nil, SlotNotSet
	}
	cert, err := k.card.Attest(*k.slot)
	if err != nil {
		return nil, err
	}
	k.Pub = cert.PublicKey

	return k, nil
}

func (k *Key) Certificate() (*x509.Certificate, error) {
	if k.card == nil {
		return nil, KeyNotInitialized
	}
	if k.slot == nil {
		return nil, SlotNotSet
	}

	return k.card.Certificate(*k.slot)
}

func (k *Key) SignerVerifier() (signature.SignerVerifier, error) {
	if k.card == nil {
		return nil, KeyNotInitialized
	}
	if k.slot == nil {
		return nil, SlotNotSet
	}
	cert, err := k.card.Attest(*k.slot)
	if err != nil {
		return nil, err
	}
	k.Pub = cert.PublicKey

	var auth piv.KeyAuth
	if k.pin == "" {
		auth.PINPrompt = getPin
	} else {
		auth.PIN = k.pin
	}
	privKey, err := k.card.PrivateKey(*k.slot, cert.PublicKey, auth)
	if err != nil {
		return nil, err
	}
	k.Priv = privKey

	return k, nil
}

func (k *Key) Sign(ctx context.Context, rawPayload []byte) ([]byte, []byte, error) {
	signer := k.Priv.(crypto.Signer)
	h := sha256.Sum256(rawPayload)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return sig, h[:], err
}

func (k *Key) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	signer := k.Priv.(crypto.Signer)
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
