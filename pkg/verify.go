package pkg

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func LoadPublicKey(keyPath string) (ed25519.PublicKey, error) {
	b, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}

	if p.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("not public: %q", p.Type)
	}
	return ed25519.PublicKey(p.Bytes), nil
}

func Verify(pubkey ed25519.PublicKey, base64sig string, payload []byte) error {
	signature, err := base64.StdEncoding.DecodeString(base64sig)
	if err != nil {
		return err
	}

	if !ed25519.Verify(pubkey, payload, signature) {
		return errors.New("unable to verify whatever")
	}

	return nil
}
