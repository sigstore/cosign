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

// +build resetyubikey
// +build e2e
// +build !pivkeydisabled

// DANGER
// This test requires a yubikey to be present. It WILL reset the yubikey to exercise functionality.
// DO NOT RUN THIS TEST IF YOU DO NOT WANT TO RESET YOUR YUBIKEY
// This requires the "resetyubikey" tag to be passed to go test.

package test

import (
	"context"
	"crypto/x509"
	"testing"

	// Import the functions directly for testing.
	. "github.com/sigstore/cosign/cmd/cosign/cli/pivcli"
)

func TestSetManagementKeyCmd(t *testing.T) {
	ctx := context.Background()

	Confirm = func(_ string) bool { return true }
	must(ResetKeyCmd(ctx), t)

	// The key should be the default management key so this should fail
	mustErr(SetManagementKeyCmd(ctx, "foobar", "newkey", false), t)
	must(SetManagementKeyCmd(ctx, "", "newkey", false), t)

	// Now it should fail with the wrong key
	mustErr(SetManagementKeyCmd(ctx, "", "otherkey", false), t)
	// But pass if we use the right key
	must(SetManagementKeyCmd(ctx, "newkey", "otherkey", false), t)

	// Reset and try a random key too!
	must(ResetKeyCmd(ctx), t)
	must(SetManagementKeyCmd(ctx, "", "", true), t)
	mustErr(SetManagementKeyCmd(ctx, "", "", true), t)
}

func TestSetPUKCmd(t *testing.T) {
	ctx := context.Background()

	Confirm = func(_ string) bool { return true }
	must(ResetKeyCmd(ctx), t)

	// The PUK should be the default key so this should fail
	mustErr(SetPukCmd(ctx, "11111111", "12121212"), t)
	must(SetPukCmd(ctx, "", "12121212"), t)

	// Now it should fail with the wrong key
	mustErr(SetPukCmd(ctx, "", "43214321"), t)
	// But pass if we use the right key
	must(SetPukCmd(ctx, "12121212", "43214321"), t)
}

func TestSetPinCmd(t *testing.T) {
	ctx := context.Background()

	Confirm = func(_ string) bool { return true }
	must(ResetKeyCmd(ctx), t)

	// The PIN should be the default PIN so this should fail
	mustErr(SetPinCmd(ctx, "111111", "222222"), t)
	must(SetPinCmd(ctx, "", "222222"), t)

	// Now it should fail with the wrong key
	mustErr(SetPinCmd(ctx, "333333", "444444"), t)
	// But pass if we use the right key
	must(SetPinCmd(ctx, "222222", "111111"), t)
}

func TestUnblockCmd(t *testing.T) {
	ctx := context.Background()

	Confirm = func(_ string) bool { return true }
	must(ResetKeyCmd(ctx), t)

	// Set a PUK
	must(SetPukCmd(ctx, "", "43214321"), t)
	// Set the pin to something, then lock the device by trying the wrong one too many times.
	must(SetPinCmd(ctx, "", "111111"), t)

	for i := 0; i < 5; i++ {
		mustErr(SetPinCmd(ctx, "222222", "333333"), t)
	}

	// Now even with the right PIN it should be stuck
	mustErr(SetPinCmd(ctx, "111111", "222222"), t)

	// But we can unblock it
	must(UnblockCmd(ctx, "43214321", "222222"), t)
	must(SetPinCmd(ctx, "222222", "333333"), t)
}

func TestGenerateKeyCmd(t *testing.T) {
	ctx := context.Background()

	Confirm = func(_ string) bool { return true }
	must(ResetKeyCmd(ctx), t)

	// This should work with the default key
	must(GenerateKeyCmd(ctx, "", false, "", "", ""), t)

	// Set the key to something other than the default
	must(SetManagementKeyCmd(ctx, "", "mynewkey", false), t)
	// Now this should fail
	mustErr(GenerateKeyCmd(ctx, "", false, "", "", ""), t)
	// Unless we use the right key
	must(GenerateKeyCmd(ctx, "mynewkey", false, "", "", ""), t)

	// Now if we use a random key it should set a new one
	must(GenerateKeyCmd(ctx, "mynewkey", true, "", "", ""), t)
	// The old one shouldn't work.
	mustErr(GenerateKeyCmd(ctx, "mynewkey", false, "", "", ""), t)
}

func TestAttestationCmd(t *testing.T) {
	ctx := context.Background()

	Confirm = func(_ string) bool { return true }
	must(ResetKeyCmd(ctx), t)
	must(GenerateKeyCmd(ctx, "", false, "", "", ""), t)

	attestations, err := AttestationCmd(ctx, "")
	if err != nil {
		t.Fatal(err)
	}

	root := x509.NewCertPool()
	if !root.AppendCertsFromPEM([]byte(yubicoCert)) {
		t.Fatal("error adding roots")
	}

	// Check the device against the manufacturer
	if _, err := attestations.DeviceCert.Verify(x509.VerifyOptions{
		Roots: root,
	}); err != nil {
		t.Fatal(err)
	}

	intermediate := x509.NewCertPool()
	intermediate.AddCert(attestations.DeviceCert)
	// Now check the key, with the device as a chain
	if _, err := attestations.KeyCert.Verify(x509.VerifyOptions{
		Roots:         root,
		Intermediates: intermediate,
	}); err != nil {
		// This is known to fail on YubiKey firmware 4.3
		// See https://labanskoller.se/blog/2019/12/30/pki-is-hard-how-yubico-trusted-openssl-and-got-it-wrong/
		//
		if attestations.KeyAttestation.Version.Major == 4 &&
			attestations.KeyAttestation.Version.Minor == 3 {
			t.Skipf("key attestation cert chain verification is known to be broken on firmware 4.3")
		} else {
			t.Fatal(err)
		}

	}

}

const yubicoCert = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----`
