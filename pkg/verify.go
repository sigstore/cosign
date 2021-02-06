package pkg

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

const pubKeyPemType = "COSIGN PUBLIC KEY"

func LoadPublicKey(keyRef string) (ed25519.PublicKey, error) {

	// The key could be plaintext or in a file.
	// First check if the file exists.
	if _, err := os.Stat(keyRef); os.IsNotExist(err) {
		// Make sure it's base64 encoded
		pubKeyBytes, err := base64.StdEncoding.DecodeString(keyRef)
		if err != nil {
			return nil, fmt.Errorf("%s must be a path to a public key or a base64 encoded public key", keyRef)
		}
		return ed25519.PublicKey(pubKeyBytes), nil
	}

	b, err := ioutil.ReadFile(keyRef)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}

	if p.Type != pubKeyPemType {
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
