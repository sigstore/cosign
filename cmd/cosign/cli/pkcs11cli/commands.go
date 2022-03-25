//go:build pkcs11key
// +build pkcs11key

// Copyright 2021 The Sigstore Authors
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

package pkcs11cli

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"golang.org/x/term"
)

type Token struct {
	Slot      uint
	TokenInfo pkcs11.TokenInfo
}

type KeyInfo struct {
	KeyLabel []byte
	KeyID    []byte
	KeyURI   string
}

func GetTokens(_ context.Context, modulePath string) ([]Token, error) {
	if modulePath == "" || !filepath.IsAbs(modulePath) {
		return nil, flag.ErrHelp
	}

	var tokens []Token

	// Initialize PKCS11 module.
	p := pkcs11.New(modulePath)
	if p == nil {
		return nil, errors.New("failed to load PKCS11 module")
	}
	err := p.Initialize()
	if err != nil {
		return nil, errors.Wrap(err, "initialize PKCS11 module")
	}
	defer p.Destroy()
	defer p.Finalize()

	// Get list of all slots with a token, and get info of each.
	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, errors.Wrap(err, "get slot list")
	}
	for _, slot := range slots {
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		tokens = append(tokens, Token{Slot: slot, TokenInfo: tokenInfo})
	}

	return tokens, nil
}

func GetKeysInfo(_ context.Context, modulePath string, slotID uint, pin string) ([]KeyInfo, error) {
	if modulePath == "" || !filepath.IsAbs(modulePath) {
		return nil, flag.ErrHelp
	}

	var keysInfo []KeyInfo

	// Initialize PKCS11 module.
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, errors.New("failed to load PKCS11 module")
	}
	err := ctx.Initialize()
	if err != nil {
		return nil, errors.Wrap(err, "initialize PKCS11 module")
	}
	defer ctx.Destroy()
	defer ctx.Finalize()

	// Get token Info.
	var tokenInfo pkcs11.TokenInfo
	tokenInfo, err = ctx.GetTokenInfo(uint(slotID))
	if err != nil {
		return nil, errors.Wrap(err, "get token info")
	}

	// If pin was not given, check COSIGN_PKCS11_PIN environment variable.
	if pin == "" {
		pin = os.Getenv("COSIGN_PKCS11_PIN")

		// If COSIGN_PKCS11_PIN was not set, check if CKF_LOGIN_REQUIRED is set in Token Info.
		// If it is, ask the user for the PIN, otherwise, do not.
		if pin == "" {
			if tokenInfo.Flags&pkcs11.CKF_LOGIN_REQUIRED == pkcs11.CKF_LOGIN_REQUIRED {
				fmt.Fprintf(os.Stderr, "Enter PIN for PKCS11 token '%s': ", tokenInfo.Label)
				// Unnecessary convert of syscall.Stdin on *nix, but Windows is a uintptr
				// nolint:unconvert
				b, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return nil, errors.Wrap(err, "get pin")
				}
				pin = string(b)
			}
		}
	}

	// Open a new session to the token.
	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, errors.Wrap(err, "open session")
	}
	defer ctx.CloseSession(session)

	// Login user.
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return nil, errors.Wrap(err, "login")
	}
	defer ctx.Logout(session)

	// Look for private keys.
	maxHandlePerFind := 20
	var handles []pkcs11.ObjectHandle
	findAttributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	if err = ctx.FindObjectsInit(session, findAttributes); err != nil {
		return nil, errors.Wrap(err, "init find objects")
	}
	newhandles, _, err := ctx.FindObjects(session, maxHandlePerFind)
	if err != nil {
		return nil, errors.Wrap(err, "find objects")
	}
	for len(newhandles) > 0 {
		handles = append(handles, newhandles...)
		newhandles, _, err = ctx.FindObjects(session, maxHandlePerFind)
		if err != nil {
			return nil, errors.Wrap(err, "find objects")
		}
	}
	err = ctx.FindObjectsFinal(session)
	if err != nil {
		return nil, errors.Wrap(err, "finalize find objects")
	}

	// For each private key, get key label and key id then construct uri.
	for _, handle := range handles {
		var keyInfo KeyInfo

		attributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		}
		if attributes, err = ctx.GetAttributeValue(session, handle, attributes); err != nil {
			return nil, errors.Wrap(err, "get attributes")
		}
		keyID := attributes[0].Value
		keyLabel := attributes[1].Value
		slotIDInt := int(slotID)

		// If the object has neither a key id nor a key label, we skip it.
		if (keyID == nil || len(keyID) == 0) && (keyLabel == nil || len(keyLabel) == 0) {
			continue
		}

		// Construct the PKCS11 URI.
		pkcs11Uri := pkcs11key.NewPkcs11UriConfigFromInput(modulePath, &slotIDInt, tokenInfo.Label, keyLabel, keyID, pin)
		pkcs11UriStr, err := pkcs11Uri.Construct()
		if err != nil {
			return nil, errors.Wrap(err, "construct pkcs11 uri")
		}

		if keyLabel != nil && len(keyLabel) != 0 {
			keyInfo.KeyLabel = keyLabel
		}
		if keyID != nil && len(keyID) != 0 {
			keyInfo.KeyID = keyID
		}
		keyInfo.KeyURI = pkcs11UriStr
		keysInfo = append(keysInfo, keyInfo)
	}

	return keysInfo, nil
}

func ListTokensCmd(ctx context.Context, modulePath string) error {

	tokens, err := GetTokens(ctx, modulePath)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\nListing tokens of PKCS11 module '%s'\n", modulePath)
	for _, token := range tokens {
		fmt.Fprintf(os.Stdout, "Token in slot %d\n", token.Slot)
		fmt.Fprintf(os.Stdout, "\tLabel: %s\n", token.TokenInfo.Label)
		fmt.Fprintf(os.Stdout, "\tManufacturer: %s\n", token.TokenInfo.ManufacturerID)
		fmt.Fprintf(os.Stdout, "\tModel: %s\n", token.TokenInfo.Model)
		fmt.Fprintf(os.Stdout, "\tS/N: %s\n\n", token.TokenInfo.SerialNumber)
	}

	return nil
}

func ListKeysUrisCmd(ctx context.Context, modulePath string, slotID uint, pin string) error {

	keysInfo, err := GetKeysInfo(ctx, modulePath, slotID, pin)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\nListing URIs of keys in slot '%d' of PKCS11 module '%s'\n", slotID, modulePath)
	for i, keyInfo := range keysInfo {
		fmt.Fprintf(os.Stdout, "Object %d\n", i)
		if keyInfo.KeyLabel != nil && len(keyInfo.KeyLabel) != 0 {
			fmt.Fprintf(os.Stdout, "\tLabel: %s\n", string(keyInfo.KeyLabel))
		}
		if keyInfo.KeyID != nil && len(keyInfo.KeyID) != 0 {
			fmt.Fprintf(os.Stdout, "\tID: %s\n", hex.EncodeToString(keyInfo.KeyID))
		}
		fmt.Fprintf(os.Stdout, "\tURI: %s\n", keyInfo.KeyURI)
	}

	return nil
}
