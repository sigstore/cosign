//go:build pkcs11key
// +build pkcs11key

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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/ThalesIgnite/crypto11"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/term"
)

var (
	ContextNotInitialized error = errors.New("context not initialized")
	SignerNotSet          error = errors.New("signer not set")
	CertNotSet            error = errors.New("certificate not set")
)

type Key struct {
	ctx    *crypto11.Context
	signer crypto.Signer
	cert   *x509.Certificate
}

func GetKeyWithURIConfig(config *Pkcs11UriConfig, askForPinIfNeeded bool) (*Key, error) {
	conf := &crypto11.Config{
		Path: config.modulePath,
		Pin:  config.pin,
	}

	// At least one of object and id must be specified.
	if (config.keyLabel == nil || len(config.keyLabel) == 0) && (config.keyID == nil || len(config.keyID) == 0) {
		return nil, errors.New("one of keyLabel and keyID must be set")
	}

	// At least one of token and slot-id must be specified.
	if config.tokenLabel == "" && config.slotID == nil {
		return nil, errors.New("one of token and slot id must be set")
	}

	// If no PIN was specified, and if askForPinIfNeeded is true, check to see if COSIGN_PKCS11_PIN env var is set.
	if conf.Pin == "" && askForPinIfNeeded {
		conf.Pin = os.Getenv("COSIGN_PKCS11_PIN")

		// If COSIGN_PKCS11_PIN not set, check to see if CKF_LOGIN_REQUIRED is set in Token Info.
		// If it is, and if askForPinIfNeeded is true, ask the user for the PIN, otherwise, do not.
		if conf.Pin == "" {
			p := pkcs11.New(config.modulePath)
			if p == nil {
				return nil, errors.New("failed to load PKCS11 module")
			}
			err := p.Initialize()
			if err != nil {
				return nil, errors.Wrap(err, "initialize PKCS11 module")
			}

			var tokenInfo pkcs11.TokenInfo
			if config.slotID != nil {
				tokenInfo, err = p.GetTokenInfo(uint(*config.slotID))
				if err != nil {
					return nil, errors.Wrap(err, "get token info")
				}
			} else {
				slots, err := p.GetSlotList(true)
				if err != nil {
					return nil, errors.Wrap(err, "get slot list of PKCS11 module")
				}

				for _, slot := range slots {
					currentTokenInfo, err := p.GetTokenInfo(slot)
					if err != nil {
						return nil, errors.Wrap(err, "get token info")
					}
					if currentTokenInfo.Label == config.tokenLabel {
						tokenInfo = currentTokenInfo
						break
					}
				}
			}

			if tokenInfo.Flags&pkcs11.CKF_LOGIN_REQUIRED == pkcs11.CKF_LOGIN_REQUIRED {
				fmt.Fprintf(os.Stderr, "Enter PIN for key '%s' in PKCS11 token '%s': ", config.keyLabel, config.tokenLabel)
				b, err := term.ReadPassword(0)
				if err != nil {
					return nil, errors.Wrap(err, "get pin")
				}
				conf.Pin = string(b)
			}

			p.Finalize()
			p.Destroy()
		}
	}

	// We must set one SlotID or tokenLabel, never both.
	// SlotID has priority over tokenLabel.
	if config.slotID != nil {
		conf.SlotNumber = config.slotID
	} else if config.tokenLabel != "" {
		conf.TokenLabel = config.tokenLabel
	}

	ctx, err := crypto11.Configure(conf)
	if err != nil {
		return nil, err
	}

	// If both keyID and keyLabel are set, keyID has priority.
	var signer crypto11.Signer
	if config.keyID != nil && len(config.keyID) != 0 {
		signer, err = ctx.FindKeyPair(config.keyID, nil)
	} else if config.keyLabel != nil && len(config.keyLabel) != 0 {
		signer, err = ctx.FindKeyPair(nil, config.keyLabel)
	}
	if err != nil {
		return nil, err
	}

	// Key's corresponding cert might not exist,
	// therefore, we do not fail if it is the case.
	var cert *x509.Certificate
	if config.keyID != nil && len(config.keyID) != 0 {
		cert, _ = ctx.FindCertificate(config.keyID, nil, nil)
	} else if config.keyLabel != nil && len(config.keyLabel) != 0 {
		cert, _ = ctx.FindCertificate(nil, config.keyLabel, nil)
	}

	return &Key{ctx: ctx, signer: signer, cert: cert}, nil
}

func (k *Key) Certificate() (*x509.Certificate, error) {
	return k.cert, nil
}

func (k *Key) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return k.signer.Public(), nil
}

func (k *Key) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	sig, err := io.ReadAll(signature)
	if err != nil {
		return errors.Wrap(err, "read signature")
	}
	msg, err := io.ReadAll(message)
	if err != nil {
		return errors.Wrap(err, "read message")
	}
	digest := sha256.Sum256(msg)

	switch kt := k.signer.Public().(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(kt, digest[:], sig) {
			return nil
		}
		return errors.New("invalid ecdsa signature")
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(kt, crypto.SHA256, digest[:], sig)
	}

	return fmt.Errorf("unsupported key type: %T", k.PublicKey)
}

func (k *Key) Verifier() (signature.Verifier, error) {
	if k.ctx == nil {
		return nil, ContextNotInitialized
	}
	if k.signer == nil {
		return nil, SignerNotSet
	}
	return k, nil
}

func (k *Key) Sign(ctx context.Context, rawPayload []byte) ([]byte, []byte, error) {
	h := sha256.Sum256(rawPayload)
	sig, err := k.signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return sig, h[:], err
}

func (k *Key) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, message); err != nil {
		return nil, err
	}
	sig, err := k.signer.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return sig, err
}

func (k *Key) SignerVerifier() (signature.SignerVerifier, error) {
	if k.ctx == nil {
		return nil, ContextNotInitialized
	}
	if k.signer == nil {
		return nil, SignerNotSet
	}
	return k, nil
}

func (k *Key) Close() {
	k.ctx.Close()

	k.signer = nil
	k.cert = nil
	k.ctx = nil
}
