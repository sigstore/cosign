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

//go:build !pkcs11keydisabled && softhsm
// +build !pkcs11keydisabled,softhsm

// DANGER
// This test requires SoftHSMv2 to be installed. An initialized token should already exist.
// This test will import an RSA key pair, using the specified token label.
// By default, the test assumes the following :
//	- The SoftHSMv2 library is located at "/usr/local/lib/softhsm/libsofthsm2.so"
//	- The initialized token has the label "My Token"
//	- The initialized token has the pin "1234"
//	- The test will import the key pair using the key label "My Key"
// These values can be overriden using the following environment variable :
//	- SOFTHSM_LIB
// 	- SOFTHSM_TOKENLABEL
// 	- SOFTHSM_PIN
// 	- SOFTHSM_KEYLABEL
// By default, the test makes use of the following SoftHSMv2 configuration files :
//	- /etc/softhsm2.conf
// 	- /etc/softhsm.conf
// These values can be overriden using the following environment variable :
//	- SOFTHSM2_CONF
// 	- SOFTHSM_CONF

package test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	// Import the functions directly for testing.

	"github.com/miekg/pkcs11"
	. "github.com/sigstore/cosign/cmd/cosign/cli/pkcs11cli"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/stretchr/testify/require"
)

var (
	modulePath = "/usr/local/lib/softhsm/libsofthsm2.so"
	tokenLabel = "My Token"
	pin        = "1234"
	keyLabel   = "My Key"

	keyID = "355d2d0b569a2a0169e46b82e172cf99aca41400"
	uri   = ""
)

func init() {
	if x := os.Getenv("SOFTHSM_LIB"); x != "" {
		modulePath = x
	}
	if x := os.Getenv("SOFTHSM_TOKENLABEL"); x != "" {
		tokenLabel = x
	}
	if x := os.Getenv("SOFTHSM_PIN"); x != "" {
		pin = x
	}
	if x := os.Getenv("SOFTHSM_KEYLABEL"); x != "" {
		keyLabel = x
	}
	if x := os.Getenv("SOFTHSM_CONF"); x == "" {
		os.Setenv("SOFTHSM_CONF", "/etc/softhsm.conf")
	}
	if x := os.Getenv("SOFTHSM2_CONF"); x == "" {
		os.Setenv("SOFTHSM2_CONF", "/etc/softhsm2.conf")
	}

	keyIDBytes, _ := hex.DecodeString(keyID)
	pkcs11UriConfig := pkcs11key.NewPkcs11UriConfigFromInput(modulePath, nil, tokenLabel, []byte(keyLabel), keyIDBytes, pin)
	uri, _ = pkcs11UriConfig.Construct()
}

func TestParsePKCS11URI(t *testing.T) {
	_ = context.Background()

	uriString := "pkcs11:"
	uriString += "library-manufacturer=manufacturer;library-description=description;library-version=1;"
	uriString += "slot-manufacturer=manufacturer;slot-description=description;slot-id=1;"
	uriString += "manufacturer=manufacturer;model=model;serial=12345678;token=token%20label;"
	uriString += "type=private;object=key%20label;id=%6b%65%79%5f%69%64"
	uriString += "?"
	uriString += "module-path=/path/to/some%20folder/libmodule.so&module-name=libmodule.so&"
	uriString += "pin-value=1234&pin-source=/path/to/pinfile"

	pkcs11UriConfig := pkcs11key.NewPkcs11UriConfig()
	must(pkcs11UriConfig.Parse(uriString), t)
	require.Equal(t, pkcs11UriConfig.KeyID, []byte("key_id"))
	require.Equal(t, pkcs11UriConfig.KeyLabel, []byte("key label"))
	require.Equal(t, pkcs11UriConfig.ModulePath, "/path/to/some folder/libmodule.so")
	require.Equal(t, pkcs11UriConfig.Pin, "1234")
	require.Equal(t, *pkcs11UriConfig.SlotID, 1)
	require.Equal(t, pkcs11UriConfig.TokenLabel, "token label")
}

func TestConstructPKCS11URI(t *testing.T) {
	_ = context.Background()

	uri := "pkcs11:token=token%20label;slot-id=1;id=%6b%65%79%5f%69%64;object=key%20label"
	uri += "?"
	uri += "module-path=/path/to/some%20folder/libmodule.so&pin-value=1234"

	slotID := 1
	pkcs11UriConfig := pkcs11key.NewPkcs11UriConfigFromInput("/path/to/some folder/libmodule.so", &slotID, "token label", []byte("key label"), []byte("key_id"), "1234")
	uriString, err := pkcs11UriConfig.Construct()
	require.NoError(t, err)
	require.Equal(t, uri, uriString)
}

func TestListTokensCmd(t *testing.T) {
	ctx := context.Background()

	tokens, err := GetTokens(ctx, modulePath)
	if err != nil {
		t.Fatal(err)
	}

	bTokenFound := false
	for _, token := range tokens {
		if token.TokenInfo.Label == tokenLabel {
			bTokenFound = true
			break
		}
	}

	if !bTokenFound {
		t.Fatalf("token with label '%s' not found", tokenLabel)
	}
}

func TestListKeysUrisCmd(t *testing.T) {
	ctx := context.Background()

	tokens, err := GetTokens(ctx, modulePath)
	if err != nil {
		t.Fatal(err)
	}

	bTokenFound := false
	var slotID uint
	for _, token := range tokens {
		if token.TokenInfo.Label == tokenLabel {
			bTokenFound = true
			slotID = token.Slot
			break
		}
	}
	if !bTokenFound {
		t.Fatalf("token with label '%s' not found", tokenLabel)
	}

	err = importKey(slotID)
	if err != nil {
		t.Fatal(err)
	}
	defer deleteKey(slotID)

	keysInfo, err := GetKeysInfo(ctx, modulePath, slotID, pin)
	if err != nil {
		t.Fatal(err)
	}

	bKeyFound := false
	for _, keyInfo := range keysInfo {
		if hex.EncodeToString(keyInfo.KeyID) == keyID && string(keyInfo.KeyLabel) == keyLabel {
			foundUriConfig := pkcs11key.NewPkcs11UriConfig()
			err = foundUriConfig.Parse(keyInfo.KeyURI)
			if err != nil {
				t.Fatal(err)
			}

			uriConfig := pkcs11key.NewPkcs11UriConfig()
			err = uriConfig.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}

			if foundUriConfig.TokenLabel == uriConfig.TokenLabel &&
				bytes.Compare(foundUriConfig.KeyID, uriConfig.KeyID) == 0 &&
				bytes.Compare(foundUriConfig.KeyLabel, uriConfig.KeyLabel) == 0 &&
				foundUriConfig.ModulePath == uriConfig.ModulePath &&
				foundUriConfig.Pin == uriConfig.Pin {
				bKeyFound = true
			}

			break
		}
	}

	if !bKeyFound {
		t.Fatalf("key not found")
	}
}

func TestSignAndVerify(t *testing.T) {
	ctx := context.Background()

	tokens, err := GetTokens(ctx, modulePath)
	if err != nil {
		t.Fatal(err)
	}

	bTokenFound := false
	var slotID uint
	for _, token := range tokens {
		if token.TokenInfo.Label == tokenLabel {
			bTokenFound = true
			slotID = token.Slot
			break
		}
	}
	if !bTokenFound {
		t.Fatalf("token with label '%s' not found", tokenLabel)
	}

	err = importKey(slotID)
	if err != nil {
		t.Fatal(err)
	}
	defer deleteKey(slotID)

	pkcs11UriConfig := pkcs11key.NewPkcs11UriConfig()
	err = pkcs11UriConfig.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}

	sk, err := pkcs11key.GetKeyWithURIConfig(pkcs11UriConfig, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Close()

	sv, err := sk.SignerVerifier()
	if err != nil {
		t.Fatal(err)
	}

	v, err := sk.Verifier()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := sv.SignMessage(bytes.NewReader([]byte("hello, world!")))
	if err != nil {
		t.Fatal(err)
	}

	err = v.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte("hello, world!")))
	if err != nil {
		t.Fatal(err)
	}
}

var newPublicKeyAttrs = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
}

var newPrivateKeyAttrs = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
}

func rsaImportAttrs(priv *rsa.PrivateKey) (pubAttrs, privAttrs []*pkcs11.Attribute) {
	pubAttrs = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(priv.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, priv.N.Bytes()),
	}
	privAttrs = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(priv.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, priv.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, priv.D.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, priv.Primes[0].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, priv.Primes[1].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, priv.Precomputed.Dp.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, priv.Precomputed.Dq.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, priv.Precomputed.Qinv.Bytes()),
	}
	return
}

func attrConcat(attrSets ...[]*pkcs11.Attribute) []*pkcs11.Attribute {
	ret := make([]*pkcs11.Attribute, 0)
	for _, attrs := range attrSets {
		ret = append(ret, attrs...)
	}
	return ret
}

func initPKCS11(modulePath string) (*pkcs11.Ctx, error) {
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("unable to load PKCS#11 module")
	}

	err := ctx.Initialize()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize PKCS#11 module")
	}

	return ctx, nil
}

func importKey(slotID uint) error {
	var pemBytes []byte
	var priv interface{}

	ctx, err := initPKCS11(modulePath)
	if err != nil {
		return err
	}
	defer func() {
		ctx.Finalize()
		ctx.Destroy()
	}()

	keyIDBytes, err := hex.DecodeString(keyID)
	if err != nil {
		return err
	}
	keyLabelBytes := []byte(keyLabel)

	r := strings.NewReader(rsaPrivKey)
	pemBytes, err = os.ReadAll(r)
	if err != nil {
		return fmt.Errorf("unable to read pem")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("unable to decode pem")
	}
	priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("unable to parse pem")
	}
	privKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unable to load key")
	}

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("unable to open session")
	}
	defer ctx.CloseSession(session)
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return fmt.Errorf("unable to login")
	}
	defer ctx.Logout(session)

	keyType := pkcs11.CKK_RSA
	pubTypeAttrs, privTypeAttrs := rsaImportAttrs(privKey)
	commonAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyIDBytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabelBytes),
	}
	pubAttrs := attrConcat(commonAttrs, newPublicKeyAttrs, pubTypeAttrs)
	privAttrs := attrConcat(commonAttrs, newPrivateKeyAttrs, privTypeAttrs)
	pubHandle, err := ctx.CreateObject(session, pubAttrs)
	if err != nil {
		return fmt.Errorf("unable to create public key")
	}
	_, err = ctx.CreateObject(session, privAttrs)
	if err != nil {
		ctx.DestroyObject(session, pubHandle)
		return fmt.Errorf("unable to create private key")
	}

	return nil
}

func deleteKey(slotID uint) error {
	var handles []pkcs11.ObjectHandle

	ctx, err := initPKCS11(modulePath)
	if err != nil {
		return err
	}
	defer func() {
		ctx.Finalize()
		ctx.Destroy()
	}()

	keyIDBytes, err := hex.DecodeString(keyID)
	if err != nil {
		return err
	}
	keyLabelBytes := []byte(keyLabel)

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("unable to open session")
	}
	defer ctx.CloseSession(session)
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return fmt.Errorf("unable to login")
	}
	defer ctx.Logout(session)

	maxHandlePerFind := 20
	publicAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyIDBytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabelBytes),
	}
	if err = ctx.FindObjectsInit(session, publicAttrs); err != nil {
		return fmt.Errorf("unable to initialize find objects")
	}
	handles, _, err = ctx.FindObjects(session, maxHandlePerFind)
	if err != nil {
		return fmt.Errorf("unable to find objects")
	}
	err = ctx.FindObjectsFinal(session)
	if err != nil {
		return fmt.Errorf("unable to finalize find objects")
	}
	if len(handles) == 1 {
		ctx.DestroyObject(session, handles[0])
		if err != nil {
			return fmt.Errorf("unable to destroy public key")
		}
	}

	privAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyIDBytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabelBytes),
	}
	if err = ctx.FindObjectsInit(session, privAttrs); err != nil {
		return fmt.Errorf("unable to initialize find objects")
	}
	handles, _, err = ctx.FindObjects(session, maxHandlePerFind)
	if err != nil {
		return fmt.Errorf("unable to find objects")
	}
	err = ctx.FindObjectsFinal(session)
	if err != nil {
		return fmt.Errorf("unable to finalize find objects")
	}
	if len(handles) == 1 {
		ctx.DestroyObject(session, handles[0])
		if err != nil {
			return fmt.Errorf("unable to destroy private key")
		}
	}

	return nil
}

func must(err error, t *testing.T) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustErr(err error, t *testing.T) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
}

const rsaPrivKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDZJZ44vB04D2wm
xz+3upmuWelrTWcceVC2v6fkBo9dIR9IejolFY+CsMF1Rc5LGXG3XStQHRrbmq1w
UxC8jsIOK7gI2xI9IOwCgyaQun3J+1VQc6eZxHLGQfTTNq7Vx67VOG8V8d3RhN7L
BvAMT5U55254bUgH0KVx5C1ybLcX6BdGaABCunh7tV+thgwEZSbr2/t0Tf8QneMr
eHojTKZp7/d90TH8KF+/FiPWJWWv5OVhjpZPwTWqUgL+6pgrMKUSWD/92JSDIZe6
UjxASE4JgnJWMQUhkerJ7j5P16gjdAwJAAt5m3L6wdfVQG2aZ9CJzUowk12ly4Dc
Dx73/UufAgMBAAECggEAF8iA/eHMqXk29UBZgDwV3PzIDhKaOoonBv0S3GzDgwW/
sWaBu9ISt9O4PKn6oEsXI2g2+D1X1bmpSWYvrRdNtdOgAohMBRn3/4Zx0OQ8JsU6
YOdp8fOMRp6uu/t/RrbqNTxLHnIxQ2N0K3SFEjQdOgxZEyOVAhYeKM0/FQtHOnzj
WoyZHT8pV3mr6WnxBw/4u/1Ahfau7fs6aVJLECc9jGF/6e7aQeb+yEeLrHayml8e
sbBx4l/1LqU/2S7SQrWtQ+fi+/MlgxvLh0XC7tTPP6I3cTetyMZime9EwwDiPebX
PLUgo8Kf/sHzd/25G9M3Yz+UCLemcPSMUjBUQTPtYQKBgQD8lnpjekyeOjNCdRVP
5w6h1wGN4aC4bCksZ89HKpHc44+3AjDT/aVviory+CyOj05qbXDdpNnNh+jl5llM
yDw15WIvSsXFx3UQ467VVrBKm7vr+k1LGgLJ2fSFbZUTyLvwW4NpP26KDW6SitZ8
B9lkepTZ0G4Eao51VgidHsulKQKBgQDcFJNAIctqUWDli4tA5L0G5tiypcAA7iIZ
0h2YK+7eOU2f3r8aaywbPhcRn+cKlrf3iV4BCZAv59WEJqq1HOlzU92jkmZspYPq
8kSZLaaiDIBw+vwV4prHDSdZFEY+hHq5eULPIgVm/M474JcghetkVt8pG3ee+Dml
o6zUrZr7hwKBgQDCiXbrpObbuoF+PsTSTGfFl923k74ALDWt4KoQ6qV61bz7O3G1
5BYFiVOo/CD9Dzxa1b1mx6+ED5f9cOL4MwPEks2DFPircgoknucpomGWpMkgXyAm
pnrdUcN0/Egj+6db4G+eoN8W7m9p6Ap3bmgtbge0lkYVmqfrkP6DXJOFuQKBgHA/
hkMFeYyGaRdqruGwSMEGaKvlYiKXUok8459DeReavn61y16cHujeKEHy/pImATqd
s3Zv/DyS0BIQ7qxlTKRnt/m/p8HuQXRJkLdX009/dNsrB/vZkfvIN7N1ZcZpJ3cF
5A9lWMAIXN+pUythYofQzw1WVxKbpDtZWcM3sH5tAoGBAMHgZdtmIyllx/1BbYSg
Emxj3LekvZL0e7afeod9f977ZETt/imaejnJNnGOPeSbtLSPfhwonLEp+5XmICzt
lJZAF8iP2m1n9h8sZga5rZQ0JgiwVNFNwde4sp1pD5UcFrYepHRxKPo50eJi3rhR
SwNAKWa96qm5o8BaQu/aRMRu
-----END PRIVATE KEY-----`

const rsaCert = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUL7BdF7HSUwEAdqElJjVLQYd2OekwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTExMDIxNzM3MzJaFw0zMTEw
MzExNzM3MzJaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDZJZ44vB04D2wmxz+3upmuWelrTWcceVC2v6fkBo9d
IR9IejolFY+CsMF1Rc5LGXG3XStQHRrbmq1wUxC8jsIOK7gI2xI9IOwCgyaQun3J
+1VQc6eZxHLGQfTTNq7Vx67VOG8V8d3RhN7LBvAMT5U55254bUgH0KVx5C1ybLcX
6BdGaABCunh7tV+thgwEZSbr2/t0Tf8QneMreHojTKZp7/d90TH8KF+/FiPWJWWv
5OVhjpZPwTWqUgL+6pgrMKUSWD/92JSDIZe6UjxASE4JgnJWMQUhkerJ7j5P16gj
dAwJAAt5m3L6wdfVQG2aZ9CJzUowk12ly4DcDx73/UufAgMBAAGjUzBRMB0GA1Ud
DgQWBBRokgD44sdsSGQEQcbJ3vrCrXTIcTAfBgNVHSMEGDAWgBRokgD44sdsSGQE
QcbJ3vrCrXTIcTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA8
+CpbIGi4ycCcSeomBzGVXsTFgFutqqvh3BFQ1u6bPlV7hIlFd11zzgWBeKKxREJn
z3SipT1qGX+uP4iVhUux94f2rQCV25mJNRKft2phAUylMr+laiO7IkHFB1zzJTfz
Bi9gm55HGvGCIdSWFkLZ/MUNCMj3WtPrUYl5jqFgDDmCpLctmPoN4vxSa0of3apv
ILH8jSsN5XbL8G1hsT/IGlRRbzoiLCKgCp6e6TjZSq/Y+JWGyw/+sZJMI8Mg4Mje
054uJhD29xmbfxdYxrMWLAFb6yoWVbDJPdECFf9uwOXyDZ8bGd48frTdUU3Rb+m3
5Hue2g5US98p2jnJiv75
-----END CERTIFICATE-----`
