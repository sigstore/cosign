package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/term"
)

func GenerateKeyPair() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign generate-key-pair", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:       "generate-key-pair",
		ShortUsage: "cosign generate-key-pair",
		ShortHelp:  "generate-key-pair generates a key-pair",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return generateKeyPair(ctx)
		},
	}
}

func generateKeyPair(ctx context.Context) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// Encrypt the private key and store it.
	password, err := getPass()
	if err != nil {
		return err
	}
	var pb *pem.Block

	pb, err = x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", priv, password, x509.PEMCipherAES256)
	if err != nil {
		return err
	}

	privBytes := pem.EncodeToMemory(pb)
	if err := ioutil.WriteFile("cosign.key", privBytes, 0600); err != nil {
		return err
	}

	// Now do the public key
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pub,
	})
	if err := ioutil.WriteFile("cosign.pub", pubBytes, 0600); err != nil {
		return err
	}
	return nil
}

func getPass() ([]byte, error) {
	fmt.Print("Enter password for private key: ")
	pw1, err := term.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return nil, err
	}
	fmt.Print("Enter again: ")
	pw2, err := term.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return nil, err
	}

	if string(pw1) != string(pw2) {
		return nil, errors.New("passwords do not match")
	}
	return pw1, nil
}
