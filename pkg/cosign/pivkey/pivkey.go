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
	"bytes"
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
	"strings"
	"syscall"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/term"
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

type selectableCard interface {
	Serial() (uint32, error)
	PublicKey(piv.Slot) (crypto.PublicKey, error)
	Close() error
}

type pivCard struct {
	*piv.YubiKey
}

func (c *pivCard) PublicKey(slot piv.Slot) (crypto.PublicKey, error) {
	cert, err := c.Certificate(slot)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey, nil
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
	return GetKeyWithSlotAndSelector(slot, Selector{})
}

// GetKeyWithSlotAndSelector opens the only attached PIV card, or selects one
// from multiple attached cards using selector. When both selector fields are
// supplied, they must match the same card.
func GetKeyWithSlotAndSelector(slot string, selector Selector) (*Key, error) {
	normalized, err := normalizeSelector(selector)
	if err != nil {
		return nil, err
	}

	pivSlot := SlotForName(slot)
	if pivSlot == nil {
		return nil, fmt.Errorf("invalid PIV slot %q", slot)
	}

	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("list PIV cards: %w", err)
	}
	if len(cards) == 0 {
		return nil, errors.New("no cards found")
	}

	open := func(name string) (selectableCard, error) {
		yk, err := piv.Open(name)
		if err != nil {
			return nil, err
		}
		return &pivCard{YubiKey: yk}, nil
	}

	if normalized.serial == nil && normalized.keySHA256 == nil {
		if len(cards) > 1 {
			return nil, multipleCardsError(cards, open, *pivSlot)
		}
		selected, err := open(cards[0])
		if err != nil {
			return nil, fmt.Errorf("open key: %w", err)
		}
		card := selected.(*pivCard)
		return &Key{card: card.YubiKey, slot: pivSlot}, nil
	}

	selected, err := selectCard(cards, open, *pivSlot, normalized)
	if err != nil {
		return nil, fmt.Errorf("open key: %w", err)
	}

	card := selected.(*pivCard)
	return &Key{card: card.YubiKey, slot: pivSlot}, nil
}

func multipleCardsError(cards []string, open func(string) (selectableCard, error), slot piv.Slot) error {
	var details strings.Builder
	fmt.Fprintf(&details, "found %d cards; specify --piv-serial or --piv-key-sha256 to select one:", len(cards))

	for _, name := range cards {
		fmt.Fprintf(&details, "\n- reader=%q", name)
		card, err := open(name)
		if err != nil {
			fmt.Fprintf(&details, " serial=unavailable key-sha256=unavailable error=%q", err.Error())
			continue
		}

		serial, err := card.Serial()
		if err != nil {
			fmt.Fprintf(&details, " serial=unavailable serial-error=%q", err.Error())
		} else {
			fmt.Fprintf(&details, " serial=%d", serial)
		}

		publicKey, err := card.PublicKey(slot)
		if err != nil {
			fmt.Fprintf(&details, " key-sha256=unavailable key-error=%q", err.Error())
		} else if fingerprint, err := publicKeySHA256(publicKey); err != nil {
			fmt.Fprintf(&details, " key-sha256=unavailable key-error=%q", err.Error())
		} else {
			fmt.Fprintf(&details, " key-sha256=%x", fingerprint)
		}

		_ = card.Close()
	}

	return errors.New(details.String())
}

func selectCard(cards []string, open func(string) (selectableCard, error), slot piv.Slot, selector normalizedSelector) (selectableCard, error) {
	if len(cards) == 0 {
		return nil, errors.New("no cards found")
	}

	var selected selectableCard
	var selectedName string
	var candidateErrors []error
	for _, name := range cards {
		card, err := open(name)
		if err != nil {
			candidateErrors = append(candidateErrors, fmt.Errorf("open card %q: %w", name, err))
			continue
		}

		matches, err := cardMatches(card, slot, selector)
		if err != nil {
			_ = card.Close()
			candidateErrors = append(candidateErrors, fmt.Errorf("inspect card %q: %w", name, err))
			continue
		}
		if !matches {
			_ = card.Close()
			continue
		}

		if selected != nil {
			_ = card.Close()
			_ = selected.Close()
			return nil, fmt.Errorf("PIV selector matched multiple cards (%q and %q)", selectedName, name)
		}
		selected = card
		selectedName = name
	}

	if selected != nil {
		return selected, nil
	}
	if len(candidateErrors) > 0 {
		return nil, fmt.Errorf("no card matched the PIV selector: %w", errors.Join(candidateErrors...))
	}

	return nil, errors.New("no card matched the PIV selector")
}

func cardMatches(card selectableCard, slot piv.Slot, selector normalizedSelector) (bool, error) {
	if selector.serial != nil {
		serial, err := card.Serial()
		if err != nil {
			return false, fmt.Errorf("read serial: %w", err)
		}
		if serial != *selector.serial {
			return false, nil
		}
	}

	if selector.keySHA256 != nil {
		publicKey, err := card.PublicKey(slot)
		if err != nil {
			return false, fmt.Errorf("read public key from slot: %w", err)
		}
		digest, err := publicKeySHA256(publicKey)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(digest[:], selector.keySHA256[:]) {
			return false, nil
		}
	}

	return true, nil
}

func publicKeySHA256(publicKey crypto.PublicKey) ([32]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode public key: %w", err)
	}

	return sha256.Sum256(encoded), nil
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

func (k *Key) SetManagementKey(old, new []byte) error {
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

func (k *Key) GenerateKey(mgmtKey []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
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
