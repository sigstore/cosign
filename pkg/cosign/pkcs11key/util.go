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

package pkcs11key

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func insertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	return buffer.String()
}

type Pkcs11UriConfig struct {
	uriPathAttributes  url.Values
	uriQueryAttributes url.Values

	modulePath string
	slotId     *int
	tokenLabel string
	keyLabel   []byte
	keyId      []byte
	pin        string
}

func NewPkcs11UriConfig() *Pkcs11UriConfig {
	return &Pkcs11UriConfig{
		uriPathAttributes:  make(url.Values),
		uriQueryAttributes: make(url.Values),
	}
}

func NewPkcs11UriConfigFromInput(modulePath string, slotId *int, tokenLabel string, keyLabel []byte, keyId []byte, pin string) *Pkcs11UriConfig {
	return &Pkcs11UriConfig{
		uriPathAttributes:  make(url.Values),
		uriQueryAttributes: make(url.Values),
		modulePath:         modulePath,
		slotId:             slotId,
		tokenLabel:         tokenLabel,
		keyLabel:           keyLabel,
		keyId:              keyId,
		pin:                pin,
	}
}

func (conf *Pkcs11UriConfig) Parse(uriString string) error {
	var slotId *int
	var pin string

	uri, err := url.Parse(uriString)
	if err != nil {
		return errors.Wrap(err, "parse uri")
	}
	if uri.Scheme != "pkcs11" {
		return errors.New("invalid uri: not a PKCS11 uri")
	}

	// Semicolons are no longer valid separators, therefore,
	// we need to replace all occurrences of ";" with "&"
	// in uri.Opaque and uri.RawQuery before passing them to url.ParseQuery().
	uri.Opaque = strings.ReplaceAll(uri.Opaque, ";", "&")
	uriPathAttributes, err := url.ParseQuery(uri.Opaque)
	if err != nil {
		return errors.Wrap(err, "parse uri path")
	}
	uri.RawQuery = strings.ReplaceAll(uri.RawQuery, ";", "&")
	uriQueryAttributes, err := url.ParseQuery(uri.RawQuery)
	if err != nil {
		return errors.Wrap(err, "parse uri query")
	}

	modulePath := uriQueryAttributes.Get("module-path")
	pinValue := uriQueryAttributes.Get("pin-value")
	tokenLabel := uriPathAttributes.Get("token")
	slotIdStr := uriPathAttributes.Get("slot-id")
	keyLabel := uriPathAttributes.Get("object")
	keyId := uriPathAttributes.Get("id")

	// At least one of token and slot-id must be specified.
	if tokenLabel == "" && slotIdStr == "" {
		return errors.New("invalid uri: one of token and slot-id must be set")
	}

	// slot-id, if specified, should be a number.
	if slotIdStr != "" {
		slot, err := strconv.Atoi(slotIdStr)
		if err != nil {
			return fmt.Errorf("invalid uri: slot-id '%s' is not a valid number", slotIdStr)
		}
		slotId = &slot
	}

	// If pin-value is specified, take it as it is.
	if pinValue != "" {
		pin = pinValue
	}

	// module-path should be specified and should point to the absolute path of the PKCS11 module.
	// If it is not, COSIGN_PKCS11_MODULE_PATH environment variable must be set.
	if modulePath == "" {
		modulePath = os.Getenv("COSIGN_PKCS11_MODULE_PATH")
		if modulePath == "" {
			return errors.New("invalid uri: module-path or COSIGN_PKCS11_MODULE_PATH must be set to the absolute path of the PKCS11 module")
		}
	}
	if !filepath.IsAbs(modulePath) {
		return errors.New("invalid uri: module-path or COSIGN_PKCS11_MODULE_PATH does not point to an absolute path")
	}
	info, err := os.Stat(modulePath)
	if err != nil {
		return errors.Wrap(err, "access module-path or COSIGN_PKCS11_MODULE_PATH")
	}
	if !info.Mode().IsRegular() {
		return errors.New("invalid uri: module-path or COSIGN_PKCS11_MODULE_PATH does not point to a regular file")
	}

	// At least one of object and id must be specified.
	if keyLabel == "" && keyId == "" {
		return errors.New("invalid uri: one of object and id must be set")
	}

	conf.uriPathAttributes = uriPathAttributes
	conf.uriQueryAttributes = uriQueryAttributes
	conf.modulePath = modulePath
	conf.tokenLabel = tokenLabel
	conf.slotId = slotId
	conf.keyLabel = []byte(keyLabel)
	conf.keyId = []byte(keyId) // url.ParseQuery() already calls url.QueryUnescape() on the id, so we only need to cast the result into byte array
	conf.pin = pin

	return nil
}

func (conf *Pkcs11UriConfig) Construct() (string, error) {

	uriString := ""

	// module-path should be specified and should point to the absolute path of the PKCS11 module.
	if conf.modulePath == "" {
		return uriString, errors.New("module path must be set to the absolute path of the PKCS11 module")
	}
	if !filepath.IsAbs(conf.modulePath) {
		return uriString, errors.New("module path does not point to an absolute path")
	}
	info, err := os.Stat(conf.modulePath)
	if err != nil {
		return uriString, errors.Wrap(err, "access module path")
	}
	if !info.Mode().IsRegular() {
		return uriString, errors.New("module path does not point to a regular file")
	}

	// At least one of keyLabel and keyId must be specified.
	if (conf.keyLabel == nil || len(conf.keyLabel) == 0) && (conf.keyId == nil || len(conf.keyId) == 0) {
		return uriString, errors.New("one of keyLabel and keyId must be set")
	}

	// At least one of tokenLabel and slotId must be specified.
	if conf.tokenLabel == "" && conf.slotId == nil {
		return uriString, errors.New("one of tokenLabel and slotId must be set")
	}

	// Construct the URI.
	uriString = "pkcs11:"
	// We set either of tokenLabel and slotId.
	if conf.tokenLabel != "" {
		uriString += "token=" + conf.tokenLabel
	}
	if conf.slotId != nil {
		uriString += ";slot-id=" + fmt.Sprintf("%d", *conf.slotId)
	}
	// If both keyLabel and keyId are set, keyId has priority.
	if conf.keyId != nil && len(conf.keyId) != 0 {
		keyIdStr := hex.EncodeToString(conf.keyId)

		// Need to percent escape the keyid, we do it manually.
		keyIdStr = insertInto(keyIdStr, 2, '%')
		keyIdStr = "%" + keyIdStr
		uriString += ";id=" + keyIdStr
	} else if conf.keyLabel != nil && len(conf.keyLabel) != 0 {
		uriString += ";object=" + string(conf.keyLabel)
	}
	uriString += "?module-path=" + conf.modulePath
	if conf.pin != "" {
		uriString += "&pin-value" + conf.pin
	}

	return uriString, nil
}
