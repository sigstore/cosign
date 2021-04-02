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

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/go-piv/piv-go/piv"
	"github.com/peterbourgon/ff/v3/ffcli"
)

func PivKey() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-key", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:        "piv-key",
		ShortUsage:  "cosign piv-key [TODO]",
		ShortHelp:   "piv-key contains commands to manage a hardware token",
		FlagSet:     flagset,
		Subcommands: []*ffcli.Command{SetManagementKey(), SetPin(), SetPuk(), Unblock(), Attestation(), GenerateKey()},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

func SetManagementKey() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-key set-management-key", flag.ExitOnError)

		oldKey = flagset.String("old-key", "", "existing management key, uses default if empty")
		newKey = flagset.String("new-key", "", "new management key, uses default if empty")
	)

	return &ffcli.Command{
		Name:       "set-management-key",
		ShortUsage: "cosign piv-key set-management-key",
		ShortHelp:  "set-management-key contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return SetManagementKeyCmd(ctx, *oldKey, *newKey)
		},
	}
}

func SetPuk() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-key set-puk", flag.ExitOnError)

		oldPuk = flagset.String("old-puk", "", "existing puk, uses default if empty")
		newPuk = flagset.String("new-puk", "", "new puk, uses default if empty")
	)

	return &ffcli.Command{
		Name:       "set-puk",
		ShortUsage: "cosign piv-key set-puk",
		ShortHelp:  "set-puk contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return SetPukCmd(ctx, *oldPuk, *newPuk)
		},
	}
}

func SetPin() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-key set-pin", flag.ExitOnError)

		oldPin = flagset.String("old-pin", "", "existing pin, uses default if empty")
		newPin = flagset.String("new-pin", "", "new pin, uses default if empty")
	)

	return &ffcli.Command{
		Name:       "set-pin",
		ShortUsage: "cosign piv-key set-pin",
		ShortHelp:  "set-pin contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return SetPinCmd(ctx, *oldPin, *newPin)
		},
	}
}

func Unblock() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-key unblock", flag.ExitOnError)

		oldPuk = flagset.String("puk", "", "existing puk, uses default if empty")
		newPin = flagset.String("new-pin", "", "new pin, uses default if empty")
	)

	return &ffcli.Command{
		Name:       "unblock",
		ShortUsage: "cosign piv-key unblock",
		ShortHelp:  "unblock contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return UnblockCmd(ctx, *oldPuk, *newPin)
		},
	}
}

func Attestation() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-key attestation", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:       "attestation",
		ShortUsage: "cosign piv-key attestation",
		ShortHelp:  "attestation contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return AttestationCmd(ctx)
		},
	}
}

func GenerateKey() *ffcli.Command {
	var (
		flagset       = flag.NewFlagSet("cosign piv-key generate-key", flag.ExitOnError)
		managementKey = flagset.String("management-key", "", "management key, uses default if empty")
	)

	return &ffcli.Command{
		Name:       "generate-key",
		ShortUsage: "cosign piv-key generate-key",
		ShortHelp:  "generate-key contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return GenerateKeyCmd(ctx, *managementKey)
		},
	}
}

func SetManagementKeyCmd(_ context.Context, oldKey, newKey string) error {
	yk, err := getKey()
	if err != nil {
		return err
	}
	defer yk.Close()

	oldBytes, err := keyBytes(oldKey)
	if err != nil {
		return err
	}
	newBytes, err := keyBytes(oldKey)
	if err != nil {
		return err
	}
	return yk.SetManagementKey(*oldBytes, *newBytes)
}

func SetPukCmd(_ context.Context, oldPuk, newPuk string) error {
	yk, err := getKey()
	if err != nil {
		return err
	}
	defer yk.Close()
	if oldPuk == "" {
		oldPuk = piv.DefaultPUK
	}
	if newPuk == "" {
		newPuk = piv.DefaultPUK
	}
	return yk.SetPUK(oldPuk, newPuk)
}

func UnblockCmd(_ context.Context, oldPuk, newPin string) error {
	yk, err := getKey()
	if err != nil {
		return err
	}
	defer yk.Close()
	if oldPuk == "" {
		oldPuk = piv.DefaultPUK
	}
	if newPin == "" {
		newPin = piv.DefaultPIN
	}
	return yk.Unblock(oldPuk, newPin)
}

func SetPinCmd(_ context.Context, oldPin, newPin string) error {
	yk, err := getKey()
	if err != nil {
		return err
	}
	defer yk.Close()

	if oldPin == "" {
		oldPin = piv.DefaultPIN
	}
	if newPin == "" {
		newPin = piv.DefaultPIN
	}
	return yk.SetPIN(oldPin, newPin)
}

func AttestationCmd(_ context.Context) error {
	yk, err := getKey()
	if err != nil {
		return err
	}
	defer yk.Close()
	deviceCert, err := yk.AttestationCertificate()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Printing device attestation certificate")
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: deviceCert.Raw,
	})
	fmt.Println(string(b))

	pinCert, err := yk.Attest(piv.SlotSignature)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Printing key attestation certificate")
	b = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pinCert.Raw,
	})
	fmt.Println(string(b))
	return nil
}

func GenerateKeyCmd(ctx context.Context, managementKey string) error {
	yk, err := getKey()
	if err != nil {
		return err
	}
	defer yk.Close()
	keyBytes, err := keyBytes(managementKey)
	if err != nil {
		return err
	}
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	pubKey, err := yk.GenerateKey(*keyBytes, piv.SlotSignature, key)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Generated public key")
	ecKey := pubKey.(*ecdsa.PublicKey)
	b, err := x509.MarshalPKIXPublicKey(ecKey)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	fmt.Println(string(pemBytes))
	yk.Close()
	return AttestationCmd(ctx)
}

func getKey() (*piv.YubiKey, error) {
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
	return yk, nil
}

func keyBytes(s string) (*[24]byte, error) {
	if s == "" {
		return &piv.DefaultManagementKey, nil
	}
	if len(s) > 24 {
		return nil, errors.New("key too long, must be <24 characters")
	}
	ret := [24]byte{}
	copy(ret[:], s)
	return &ret, nil
}
