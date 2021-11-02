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

	"github.com/ThalesIgnite/crypto11"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"golang.org/x/term"
)

func ListTokensCmd(_ context.Context, modulePath string) error {
	if modulePath == "" || !filepath.IsAbs(modulePath) {
		return flag.ErrHelp
	}

	// Initialize PKCS11 module.
	p := pkcs11.New(modulePath)
	if p == nil {
		return errors.New("failed to load PKCS11 module")
	}
	err := p.Initialize()
	if err != nil {
		return errors.Wrap(err, "initialize PKCS11 module")
	}
	defer p.Destroy()
	defer p.Finalize()

	// Get all slots with a token, and print info.
	slots, err := p.GetSlotList(true)
	if err != nil {
		return errors.Wrap(err, "get slot list of PKCS11 module")
	}
	fmt.Fprintf(os.Stdout, "Listing tokens of PKCS11 module '%s'\n", modulePath)
	for _, slot := range slots {
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			return errors.Wrap(err, "get token info")
		}

		fmt.Fprintf(os.Stdout, "Token in slot %d\n", slot)
		fmt.Fprintf(os.Stdout, "\tLabel: %s\n", tokenInfo.Label)
		fmt.Fprintf(os.Stdout, "\tManufacturer: %s\n", tokenInfo.ManufacturerID)
		fmt.Fprintf(os.Stdout, "\tModel: %s\n", tokenInfo.Model)
		fmt.Fprintf(os.Stdout, "\tS/N: %s\n\n", tokenInfo.SerialNumber)
	}

	return nil
}

func ListKeysUrisCmd(_ context.Context, modulePath string, SlotID uint, pin string) error {
	if modulePath == "" || !filepath.IsAbs(modulePath) {
		return flag.ErrHelp
	}

	// Initialize PKCS11 module.
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return errors.New("failed to load PKCS11 module")
	}
	err := ctx.Initialize()
	if err != nil {
		return errors.Wrap(err, "initialize PKCS11 module")
	}
	defer ctx.Destroy()
	defer ctx.Finalize()

	// Get token Info.
	var tokenInfo pkcs11.TokenInfo
	tokenInfo, err = ctx.GetTokenInfo(uint(SlotID))
	if err != nil {
		return errors.Wrap(err, "get token info")
	}

	// If pin was not given, check COSIGN_PKCS11_PIN environment variable.
	if pin == "" {
		pin = os.Getenv("COSIGN_PKCS11_PIN")

		// If COSIGN_PKCS11_PIN was not set, check if CKF_LOGIN_REQUIRED is set in Token Info.
		// If it is, ask the user for the PIN, otherwise, do not.
		if pin == "" {
			if tokenInfo.Flags&pkcs11.CKF_LOGIN_REQUIRED == pkcs11.CKF_LOGIN_REQUIRED {
				fmt.Fprintf(os.Stderr, "Enter PIN for PKCS11 token '%s': ", tokenInfo.Label)
				b, err := term.ReadPassword(0)
				if err != nil {
					return errors.Wrap(err, "get pin")
				}
				pin = string(b)
			}
		}
	}

	// Open a new session to the token.
	session, err := ctx.OpenSession(SlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return errors.Wrap(err, "open session")
	}
	defer ctx.CloseSession(session)

	// Login user.
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return errors.Wrap(err, "login")
	}
	defer ctx.Logout(session)

	// Look for private keys.
	maxHandlePerFind := 20
	var handles []pkcs11.ObjectHandle
	findAttributes := make(crypto11.AttributeSet)
	err = findAttributes.Set(crypto11.CkaClass, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return errors.Wrap(err, "set attributes")
	}
	if err = ctx.FindObjectsInit(session, findAttributes.ToSlice()); err != nil {
		return errors.Wrap(err, "init find objects")
	}
	newhandles, _, err := ctx.FindObjects(session, maxHandlePerFind)
	if err != nil {
		return errors.Wrap(err, "find objects")
	}
	for len(newhandles) > 0 {
		handles = append(handles, newhandles...)
		newhandles, _, err = ctx.FindObjects(session, maxHandlePerFind)
		if err != nil {
			return errors.Wrap(err, "find objects")
		}
	}
	err = ctx.FindObjectsFinal(session)
	if err != nil {
		return errors.Wrap(err, "finalize find objects")
	}

	// For each private key, get key label and key id then construct uri.
	i := 0
	fmt.Fprintf(os.Stdout, "Listing URIs of keys in slot '%d' of PKCS11 module '%s'\n", SlotID, modulePath)
	for _, handle := range handles {
		attributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		}
		if attributes, err = ctx.GetAttributeValue(session, handle, attributes); err != nil {
			return errors.Wrap(err, "get attributes")
		}
		keyID := attributes[0].Value
		keyLabel := attributes[1].Value

		// If the object has neither a key id nor a key label, we skip it.
		if (keyID == nil || len(keyID) == 0) && (keyLabel == nil || len(keyLabel) == 0) {
			continue
		}

		SlotIDInt := int(SlotID)
		pkcs11Uri := pkcs11key.NewPkcs11UriConfigFromInput(modulePath, &SlotIDInt, tokenInfo.Label, keyLabel, keyID, pin)
		pkcs11UriStr, err := pkcs11Uri.Construct()
		if err != nil {
			return errors.Wrap(err, "construct pkcs11 uri")
		}

		fmt.Fprintf(os.Stdout, "Object %d\n", i)
		if keyLabel != nil && len(keyLabel) != 0 {
			fmt.Fprintf(os.Stdout, "\tLabel: %s\n", string(keyLabel))
		}
		if keyID != nil && len(keyID) != 0 {
			fmt.Fprintf(os.Stdout, "\tID: %s\n", hex.EncodeToString(keyID))
		}
		fmt.Fprintf(os.Stdout, "\tURI: %s\n", pkcs11UriStr)

		i++
	}

	return nil
}
