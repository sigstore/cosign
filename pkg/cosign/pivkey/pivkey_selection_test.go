//go:build pivkey && cgo
// +build pivkey,cgo

// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pivkey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

type fakeSelectableCard struct {
	serial       uint32
	serialErr    error
	publicKey    crypto.PublicKey
	publicKeyErr error
	closed       bool
}

func (c *fakeSelectableCard) Serial() (uint32, error) {
	return c.serial, c.serialErr
}

func (c *fakeSelectableCard) PublicKey(piv.Slot) (crypto.PublicKey, error) {
	return c.publicKey, c.publicKeyErr
}

func (c *fakeSelectableCard) Close() error {
	c.closed = true
	return nil
}

func TestSelectCardBySerial(t *testing.T) {
	first := &fakeSelectableCard{serial: 1001}
	second := &fakeSelectableCard{serial: 1002}
	cards := map[string]*fakeSelectableCard{"first": first, "second": second}
	serial := uint32(1002)

	selected, err := selectCard([]string{"first", "second"}, fakeCardOpener(cards), piv.SlotSignature, normalizedSelector{serial: &serial})
	if err != nil {
		t.Fatalf("selectCard() error = %v", err)
	}
	if selected != second {
		t.Fatalf("selected = %p, want %p", selected, second)
	}
	if !first.closed {
		t.Error("nonmatching card was not closed")
	}
	if second.closed {
		t.Error("selected card was closed")
	}
}

func TestSelectCardByPublicKeySHA256(t *testing.T) {
	first := &fakeSelectableCard{publicKey: testPublicKey(1)}
	second := &fakeSelectableCard{publicKey: testPublicKey(2)}
	cards := map[string]*fakeSelectableCard{"first": first, "second": second}
	fingerprint := fingerprint(t, second.publicKey)

	selected, err := selectCard([]string{"first", "second"}, fakeCardOpener(cards), piv.SlotSignature, normalizedSelector{keySHA256: &fingerprint})
	if err != nil {
		t.Fatalf("selectCard() error = %v", err)
	}
	if selected != second {
		t.Fatalf("selected = %p, want %p", selected, second)
	}
	if !first.closed {
		t.Error("nonmatching card was not closed")
	}
	if second.closed {
		t.Error("selected card was closed")
	}
}

func TestSelectCardRequiresAllSelectorsToMatch(t *testing.T) {
	first := &fakeSelectableCard{serial: 1001, publicKey: testPublicKey(1)}
	second := &fakeSelectableCard{serial: 1002, publicKey: testPublicKey(2)}
	cards := map[string]*fakeSelectableCard{"first": first, "second": second}
	serial := uint32(1002)
	fingerprint := fingerprint(t, first.publicKey)

	_, err := selectCard([]string{"first", "second"}, fakeCardOpener(cards), piv.SlotSignature, normalizedSelector{serial: &serial, keySHA256: &fingerprint})
	if err == nil || !strings.Contains(err.Error(), "no card matched") {
		t.Fatalf("selectCard() error = %v, want no match", err)
	}
	if !first.closed || !second.closed {
		t.Error("all nonmatching cards must be closed")
	}
}

func TestSelectCardRejectsDuplicateMatches(t *testing.T) {
	first := &fakeSelectableCard{serial: 1001}
	second := &fakeSelectableCard{serial: 1001}
	cards := map[string]*fakeSelectableCard{"first": first, "second": second}
	serial := uint32(1001)

	_, err := selectCard([]string{"first", "second"}, fakeCardOpener(cards), piv.SlotSignature, normalizedSelector{serial: &serial})
	if err == nil || !strings.Contains(err.Error(), "matched multiple cards") {
		t.Fatalf("selectCard() error = %v, want duplicate match", err)
	}
	if !first.closed || !second.closed {
		t.Error("duplicate matching cards must be closed")
	}
}

func TestSelectCardReportsCandidateErrorsWhenNothingMatches(t *testing.T) {
	first := &fakeSelectableCard{serialErr: errors.New("serial unavailable")}
	cards := map[string]*fakeSelectableCard{"first": first}
	serial := uint32(1001)

	_, err := selectCard([]string{"first", "missing"}, fakeCardOpener(cards), piv.SlotSignature, normalizedSelector{serial: &serial})
	if err == nil || !strings.Contains(err.Error(), "serial unavailable") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("selectCard() error = %v, want candidate errors", err)
	}
	if !first.closed {
		t.Error("card with an inspection error was not closed")
	}
}

func TestMultipleCardsErrorListsAvailableSelectors(t *testing.T) {
	first := &fakeSelectableCard{serial: 1001, publicKey: testPublicKey(1)}
	second := &fakeSelectableCard{serial: 1002, publicKey: testPublicKey(2)}
	cards := map[string]*fakeSelectableCard{"reader one": first, "reader two": second}
	firstFingerprint := fingerprint(t, first.publicKey)
	secondFingerprint := fingerprint(t, second.publicKey)

	err := multipleCardsError([]string{"reader one", "reader two"}, fakeCardOpener(cards), piv.SlotSignature)
	message := err.Error()
	for _, want := range []string{
		"found 2 cards",
		"--piv-serial",
		"--piv-key-sha256",
		`reader="reader one"`,
		"serial=1001",
		fmt.Sprintf("key-sha256=%x", firstFingerprint),
		`reader="reader two"`,
		"serial=1002",
		fmt.Sprintf("key-sha256=%x", secondFingerprint),
	} {
		if !strings.Contains(message, want) {
			t.Errorf("multipleCardsError() = %q, want substring %q", message, want)
		}
	}
	if !first.closed || !second.closed {
		t.Error("inspected cards must be closed")
	}
}

func TestMultipleCardsErrorReportsUnavailableMetadata(t *testing.T) {
	first := &fakeSelectableCard{serialErr: errors.New("no serial"), publicKeyErr: errors.New("no certificate")}
	cards := map[string]*fakeSelectableCard{"reader": first}

	err := multipleCardsError([]string{"reader", "cannot open"}, fakeCardOpener(cards), piv.SlotSignature)
	message := err.Error()
	for _, want := range []string{
		"serial=unavailable",
		`serial-error="no serial"`,
		"key-sha256=unavailable",
		`key-error="no certificate"`,
		`reader="cannot open"`,
		`error="unknown card"`,
	} {
		if !strings.Contains(message, want) {
			t.Errorf("multipleCardsError() = %q, want substring %q", message, want)
		}
	}
	if !first.closed {
		t.Error("inspected card must be closed")
	}
}

func fakeCardOpener(cards map[string]*fakeSelectableCard) func(string) (selectableCard, error) {
	return func(name string) (selectableCard, error) {
		card, ok := cards[name]
		if !ok {
			return nil, fmt.Errorf("unknown card")
		}
		return card, nil
	}
}

func testPublicKey(fill byte) ed25519.PublicKey {
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range key {
		key[i] = fill
	}
	return key
}

func fingerprint(t *testing.T, publicKey crypto.PublicKey) [32]byte {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return sha256.Sum256(encoded)
}
