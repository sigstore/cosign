// Copyright 2026 The Sigstore Authors.
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

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"

	"github.com/sigstore/cosign/v3/internal/auth"
	"github.com/sigstore/cosign/v3/internal/key"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/blob"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	pb_go_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

type signerVerifier struct {
	Cert  []byte
	Chain []byte
	signature.SignerVerifier
	close func()
}

func (c *signerVerifier) Close() {
	if c.close != nil {
		c.close()
	}
}

func getKeypairAndToken(ctx context.Context, ko KeyOpts, cert, certChain string) (sign.Keypair, []byte, string, error) {
	var keypair sign.Keypair
	var ephemeralKeypair bool
	var idToken string
	var sv *signerVerifier
	var certBytes []byte
	var err error

	sv, ephemeralKeypair, err = signerFromKeyOpts(ctx, cert, certChain, ko)
	if err != nil {
		return nil, nil, "", fmt.Errorf("getting signer: %w", err)
	}
	keypair, err = key.NewSignerVerifierKeypair(sv, ko.DefaultLoadOptions)
	if err != nil {
		sv.Close()
		return nil, nil, "", fmt.Errorf("creating signerverifier keypair: %w", err)
	}
	certBytes = sv.Cert

	if ephemeralKeypair || ko.IssueCertificateForExistingKey {
		idToken, err = auth.RetrieveIDToken(ctx, auth.IDTokenConfig{
			TokenOrPath:      ko.IDToken,
			DisableProviders: ko.OIDCDisableProviders,
			Provider:         ko.OIDCProvider,
			AuthFlow:         ko.FulcioAuthFlow,
			SkipConfirm:      ko.SkipConfirmation,
			OIDCServices:     ko.SigningConfig.OIDCProviderURLs(),
			ClientID:         ko.OIDCClientID,
			ClientSecret:     ko.OIDCClientSecret,
			RedirectURL:      ko.OIDCRedirectURL,
		})
		if err != nil {
			sv.Close()
			return nil, nil, "", fmt.Errorf("retrieving ID token: %w", err)
		}
	}

	return keypair, certBytes, idToken, nil
}

func signerFromKeyOpts(ctx context.Context, certPath string, certChainPath string, ko KeyOpts) (*signerVerifier, bool, error) {
	var sv *signerVerifier
	var err error
	genKey := false
	switch {
	case ko.KeyRef != "":
		sv, err = signerFromKeyRef(certPath, certChainPath, ko.KeyRef, ko.PassFunc, ko.DefaultLoadOptions)
	default:
		genKey = true
		ui.Infof(ctx, "Generating ephemeral keys...")
		sv, err = signerFromNewKey(ko.SigningAlgorithm, ko.DefaultLoadOptions)
	}
	if err != nil {
		return nil, false, err
	}
	return sv, genKey, nil
}

func loadKey(keyPath string, pf func(bool) ([]byte, error), defaultLoadOptions *[]signature.LoadOption) (signature.SignerVerifier, error) {
	kb, err := blob.LoadFileOrURL(keyPath)
	if err != nil {
		return nil, err
	}
	pass := []byte{}
	if pf != nil {
		pass, err = pf(false)
		if err != nil {
			return nil, err
		}
	}
	return cosign.LoadPrivateKey(kb, pass, defaultLoadOptions)
}

func signerFromKeyRef(certPath, certChainPath, keyRef string, passFunc func(bool) ([]byte, error), defaultLoadOptions *[]signature.LoadOption) (*signerVerifier, error) {
	k, err := loadKey(keyRef, passFunc, defaultLoadOptions)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	certSigner := &signerVerifier{
		SignerVerifier: k,
	}

	var leafCert *x509.Certificate

	if certPath != "" {
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		if bytes.HasPrefix(certBytes, []byte("-----")) {
			decoded, _ := pem.Decode(certBytes)
			if decoded.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("supplied PEM file is not a certificate: %s", certPath)
			}
			certBytes = decoded.Bytes
		}
		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("parse x509 certificate: %w", err)
		}
		pk, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("get public key: %w", err)
		}
		if cryptoutils.EqualKeys(pk, parsedCert.PublicKey) != nil {
			return nil, errors.New("public key in certificate does not match the provided public key")
		}
		pemBytes, err := cryptoutils.MarshalCertificateToPEM(parsedCert)
		if err != nil {
			return nil, fmt.Errorf("marshaling certificate to PEM: %w", err)
		}
		leafCert = parsedCert
		certSigner.Cert = pemBytes
	}

	if certChainPath == "" {
		return certSigner, nil
	} else if certSigner.Cert == nil {
		return nil, errors.New("no leaf certificate found or provided while specifying chain")
	}

	certChainBytes, err := os.ReadFile(certChainPath)
	if err != nil {
		return nil, fmt.Errorf("reading certificate chain from path: %w", err)
	}
	certChain, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(certChainBytes))
	if err != nil {
		return nil, fmt.Errorf("loading certificate chain: %w", err)
	}
	if len(certChain) == 0 {
		return nil, errors.New("no certificates in certificate chain")
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certChain[len(certChain)-1])
	subPool := x509.NewCertPool()
	for _, c := range certChain[:len(certChain)-1] {
		subPool.AddCert(c)
	}
	if _, err := trustedCert(leafCert, rootPool, subPool); err != nil {
		return nil, fmt.Errorf("unable to validate certificate chain: %w", err)
	}
	certSigner.Chain = certChainBytes

	return certSigner, nil
}

func signerFromNewKey(signingAlgorithm string, defaultLoadOptions *[]signature.LoadOption) (*signerVerifier, error) {
	keyDetails, err := parseSignatureAlgorithmFlag(signingAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("parsing signature algorithm: %w", err)
	}
	algo, err := signature.GetAlgorithmDetails(keyDetails)
	if err != nil {
		return nil, fmt.Errorf("getting algorithm details: %w", err)
	}

	privKey, err := generatePrivateKeyWithAlgorithm(&algo)
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}

	defaultLoadOptions = getDefaultLoadOptions(defaultLoadOptions)
	sv, err := signature.LoadSignerVerifierFromAlgorithmDetails(privKey, algo, *defaultLoadOptions...)
	if err != nil {
		return nil, err
	}

	return &signerVerifier{
		SignerVerifier: sv,
	}, nil
}

func parseSignatureAlgorithmFlag(signingAlgorithm string) (pb_go_v1.PublicKeyDetails, error) {
	if signingAlgorithm == "" {
		var err error
		signingAlgorithm, err = signature.FormatSignatureAlgorithmFlag(pb_go_v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
		if err != nil {
			return pb_go_v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, fmt.Errorf("formatting signature algorithm: %w", err)
		}
	}
	return signature.ParseSignatureAlgorithmFlag(signingAlgorithm)
}

func generatePrivateKeyWithAlgorithm(algo *signature.AlgorithmDetails) (crypto.PrivateKey, error) {
	var currentAlgo signature.AlgorithmDetails
	if algo == nil {
		var err error
		currentAlgo, err = signature.GetAlgorithmDetails(pb_go_v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
		if err != nil {
			return nil, fmt.Errorf("error getting algorithm details for default algorithm: %w", err)
		}
	} else {
		currentAlgo = *algo
	}

	switch currentAlgo.GetKeyType() {
	case signature.ECDSA:
		curve, err := currentAlgo.GetECDSACurve()
		if err != nil {
			return nil, fmt.Errorf("error getting ECDSA curve: %w", err)
		}
		return ecdsa.GenerateKey(*curve, rand.Reader)
	case signature.RSA:
		rsaKeySize, err := currentAlgo.GetRSAKeySize()
		if err != nil {
			return nil, fmt.Errorf("error getting RSA key size: %w", err)
		}
		return rsa.GenerateKey(rand.Reader, int(rsaKeySize))
	case signature.ED25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("error generating ED25519 key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", currentAlgo.GetKeyType())
	}
}

func getDefaultLoadOptions(defaultLoadOptions *[]signature.LoadOption) *[]signature.LoadOption {
	if defaultLoadOptions == nil {
		return &[]signature.LoadOption{sigoptions.WithED25519ph()}
	}
	return defaultLoadOptions
}

func trustedCert(cert *x509.Certificate, roots *x509.CertPool, intermediates *x509.CertPool) ([][]*x509.Certificate, error) {
	chains, err := cert.Verify(x509.VerifyOptions{
		CurrentTime:   cert.NotBefore,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("cert verification failed: %w", err)
	}
	return chains, nil
}

func protoHashAlgoToHash(ha pb_go_v1.HashAlgorithm) crypto.Hash {
	switch ha {
	case pb_go_v1.HashAlgorithm_SHA2_256:
		return crypto.SHA256
	case pb_go_v1.HashAlgorithm_SHA2_384:
		return crypto.SHA384
	case pb_go_v1.HashAlgorithm_SHA2_512:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}

func generateKeyPair(prefix string, passFunc func(bool) ([]byte, error)) error {
	privateKeyPath := prefix + ".key"
	publicKeyPath := prefix + ".pub"

	if _, err := os.Stat(privateKeyPath); err == nil {
		return fmt.Errorf("file %s already exists; generation halted to prevent accidental overwrite", privateKeyPath)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	var pass []byte
	if passFunc != nil {
		pass, err = passFunc(true)
		if err != nil {
			return fmt.Errorf("getting password: %w", err)
		}
	}

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}

	encryptedBytes, err := encrypted.Encrypt(x509Encoded, pass)
	if err != nil {
		return fmt.Errorf("encrypting private key: %w", err)
	}

	privBlock := &pem.Block{
		Type:  "ENCRYPTED SIGSTORE PRIVATE KEY",
		Bytes: encryptedBytes,
	}
	privPEMBytes := pem.EncodeToMemory(privBlock)
	if err := os.WriteFile(privateKeyPath, privPEMBytes, 0600); err != nil {
		return fmt.Errorf("writing private key file: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pubPEMBytes := pem.EncodeToMemory(pubBlock)
	if err := os.WriteFile(publicKeyPath, pubPEMBytes, 0644); err != nil { //nolint: gosec
		return fmt.Errorf("writing public key file: %w", err)
	}

	return nil
}

func getPass(confirm bool) ([]byte, error) {
	pw, ok := env.LookupEnv(env.VariablePassword)
	switch {
	case ok:
		return []byte(pw), nil
	case cosign.IsTerminal():
		return cosign.GetPassFromTerm(confirm)
	default:
		return io.ReadAll(os.Stdin)
	}
}
