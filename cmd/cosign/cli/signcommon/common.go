// Copyright 2025 The Sigstore Authors.
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

package signcommon

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio/fulcioverifier"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign/privacy"
	"github.com/sigstore/cosign/v3/internal/auth"
	"github.com/sigstore/cosign/v3/internal/key"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	"github.com/sigstore/cosign/v3/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v3/pkg/cosign/pkcs11key"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/cosign/v3/pkg/types"
	pb_go_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// SignerVerifier contains keys or certs to sign and verify.
type SignerVerifier struct {
	Cert  []byte
	Chain []byte
	signature.SignerVerifier
	close func()
}

// Close closes the key context if there is one.
func (c *SignerVerifier) Close() {
	if c.close != nil {
		c.close()
	}
}

// Bytes returns the raw bytes of the cert or key.
func (c *SignerVerifier) Bytes(ctx context.Context) ([]byte, error) {
	if c.Cert != nil {
		return c.Cert, nil
	}

	pemBytes, err := sigs.PublicKeyPem(c, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return pemBytes, nil
}

// GetKeypairAndToken creates a keypair object from provided key or cert flags or generates an ephemeral key.
// For an ephemeral key, it also uses the key to fetch an OIDC token, the pair of which are later used to get a Fulcio cert.
func GetKeypairAndToken(ctx context.Context, ko options.KeyOpts, cert, certChain string) (sign.Keypair, *SignerVerifier, []byte, string, error) {
	var keypair sign.Keypair
	var ephemeralKeypair bool
	var idToken string
	var sv *SignerVerifier
	var certBytes []byte
	var err error

	sv, ephemeralKeypair, err = signerFromKeyOpts(ctx, cert, certChain, ko)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("getting signer: %w", err)
	}
	keypair, err = key.NewSignerVerifierKeypair(sv, ko.DefaultLoadOptions)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("creating signerverifier keypair: %w", err)
	}
	certBytes = sv.Cert
	defer func() {
		if sv != nil {
			sv.Close()
		}
	}()

	if ephemeralKeypair || ko.IssueCertificateForExistingKey {
		if ko.SigningConfig == nil {
			sv, err = keylessSigner(ctx, ko, sv)
		} else {
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
		}
		if err != nil {
			return nil, nil, nil, "", fmt.Errorf("retrieving ID token: %w", err)
		}
	}

	return keypair, sv, certBytes, idToken, nil
}

func keylessSigner(ctx context.Context, ko options.KeyOpts, sv *SignerVerifier) (*SignerVerifier, error) {
	var (
		k   *fulcio.Signer
		err error
	)

	if _, ok := sv.SignerVerifier.(*signature.ED25519phSignerVerifier); ok {
		return nil, fmt.Errorf("ed25519ph unsupported by Fulcio")
	}

	if ko.InsecureSkipFulcioVerify {
		if k, err = fulcio.NewSigner(ctx, ko, sv); err != nil {
			return nil, fmt.Errorf("getting key from Fulcio: %w", err)
		}
	} else {
		if k, err = fulcioverifier.NewSigner(ctx, ko, sv); err != nil {
			return nil, fmt.Errorf("getting key from Fulcio: %w", err)
		}
	}

	return &SignerVerifier{
		Cert:           k.Cert,
		Chain:          k.Chain,
		SignerVerifier: k,
	}, nil
}

// ShouldUploadToTlog determines whether the user wants to upload the entry to Rekor.
func ShouldUploadToTlog(ctx context.Context, ko options.KeyOpts, ref name.Reference, tlogUpload bool) (bool, error) {
	upload := shouldUploadToTlog(ctx, ko, ref, tlogUpload)
	var statementErr error
	if upload {
		privacy.StatementOnce.Do(func() {
			ui.Infof(ctx, privacy.Statement)
			ui.Infof(ctx, privacy.StatementConfirmation)
			if !ko.SkipConfirmation {
				if err := ui.ConfirmContinue(ctx); err != nil {
					statementErr = err
				}
			}
		})
	}
	return upload, statementErr
}

func shouldUploadToTlog(ctx context.Context, ko options.KeyOpts, ref name.Reference, tlogUpload bool) bool {
	// return false if not uploading to the tlog has been requested
	if !tlogUpload {
		return false
	}

	if ko.SkipConfirmation {
		return true
	}

	// We don't need to validate the ref, just return true
	if ref == nil {
		return true
	}

	// Check if the image is public (no auth in Get)
	if _, err := remote.Get(ref, remote.WithContext(ctx)); err != nil {
		ui.Warnf(ctx, "%q appears to be a private repository, please confirm uploading to the transparency log at %q", ref.Context().String(), ko.RekorURL)
		if ui.ConfirmContinue(ctx) != nil {
			ui.Infof(ctx, "not uploading to transparency log")
			return false
		}
	}
	return true
}

// GetSignerVerifier generates a SignerVerifier from provided key flags.
func GetSignerVerifier(ctx context.Context, cert, certChain string, ko options.KeyOpts) (*SignerVerifier, func(), error) {
	sv, genKey, err := signerFromKeyOpts(ctx, cert, certChain, ko)
	if err != nil {
		return nil, nil, fmt.Errorf("getting signer from opts: %w", err)
	}
	if genKey || ko.IssueCertificateForExistingKey {
		sv, err = keylessSigner(ctx, ko, sv)
		if err != nil {
			return nil, nil, fmt.Errorf("getting Fulcio signer: %w", err)
		}
	}
	return sv, sv.Close, nil
}

func signerFromKeyOpts(ctx context.Context, certPath string, certChainPath string, ko options.KeyOpts) (*SignerVerifier, bool, error) {
	var sv *SignerVerifier
	var err error
	genKey := false
	switch {
	case ko.Sk:
		sv, err = signerFromSecurityKey(ctx, ko.Slot)
	case ko.KeyRef != "":
		sv, err = signerFromKeyRef(ctx, certPath, certChainPath, ko.KeyRef, ko.PassFunc, ko.DefaultLoadOptions)
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

func signerFromSecurityKey(ctx context.Context, keySlot string) (*SignerVerifier, error) {
	sk, err := pivkey.GetKeyWithSlot(keySlot)
	if err != nil {
		return nil, err
	}
	sv, err := sk.SignerVerifier()
	if err != nil {
		sk.Close()
		return nil, err
	}

	// Handle the -cert flag.
	// With PIV, we assume the certificate is in the same slot on the PIV
	// token as the private key. If it's not there, show a warning to the
	// user.
	certFromPIV, err := sk.Certificate()
	var pemBytes []byte
	if err != nil {
		ui.Warnf(ctx, "no x509 certificate retrieved from the PIV token")
	} else {
		pemBytes, err = cryptoutils.MarshalCertificateToPEM(certFromPIV)
		if err != nil {
			sk.Close()
			return nil, err
		}
	}

	return &SignerVerifier{
		Cert:           pemBytes,
		SignerVerifier: sv,
		close:          sk.Close,
	}, nil
}

func signerFromKeyRef(ctx context.Context, certPath, certChainPath, keyRef string, passFunc cosign.PassFunc, defaultLoadOptions *[]signature.LoadOption) (*SignerVerifier, error) {
	k, err := sigs.SignerVerifierFromKeyRef(ctx, keyRef, passFunc, defaultLoadOptions)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	certSigner := &SignerVerifier{
		SignerVerifier: k,
	}

	var leafCert *x509.Certificate

	// Attempt to extract certificate from PKCS11 token
	// With PKCS11, we assume the certificate is in the same slot on the PKCS11
	// token as the private key. If it's not there, show a warning to the
	// user.
	if pkcs11Key, ok := k.(*pkcs11key.Key); ok {
		certFromPKCS11, _ := pkcs11Key.Certificate()
		certSigner.close = pkcs11Key.Close

		if certFromPKCS11 == nil {
			ui.Warnf(ctx, "no x509 certificate retrieved from the PKCS11 token")
		} else {
			pemBytes, err := cryptoutils.MarshalCertificateToPEM(certFromPKCS11)
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
			// Check that the provided public key and certificate key match
			pubKey, err := k.PublicKey()
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
			if cryptoutils.EqualKeys(pubKey, certFromPKCS11.PublicKey) != nil {
				pkcs11Key.Close()
				return nil, errors.New("pkcs11 key and certificate do not match")
			}
			leafCert = certFromPKCS11
			certSigner.Cert = pemBytes
		}
	}

	// Handle --cert flag
	if certPath != "" {
		// Allow both DER and PEM encoding
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		// Handle PEM
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
		if certSigner.Cert != nil {
			ui.Warnf(ctx, "overriding x509 certificate retrieved from the PKCS11 token")
		}
		leafCert = parsedCert
		certSigner.Cert = pemBytes
	}

	if certChainPath == "" {
		return certSigner, nil
	} else if certSigner.Cert == nil {
		return nil, errors.New("no leaf certificate found or provided while specifying chain")
	}

	// Handle --cert-chain flag
	// Accept only PEM encoded certificate chain
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
	// Verify certificate chain is valid
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certChain[len(certChain)-1])
	subPool := x509.NewCertPool()
	for _, c := range certChain[:len(certChain)-1] {
		subPool.AddCert(c)
	}
	if _, err := cosign.TrustedCert(leafCert, rootPool, subPool); err != nil {
		return nil, fmt.Errorf("unable to validate certificate chain: %w", err)
	}
	certSigner.Chain = certChainBytes

	return certSigner, nil
}

func signerFromNewKey(signingAlgorithm string, defaultLoadOptions *[]signature.LoadOption) (*SignerVerifier, error) {
	keyDetails, err := ParseSignatureAlgorithmFlag(signingAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("parsing signature algorithm: %w", err)
	}
	algo, err := signature.GetAlgorithmDetails(keyDetails)
	if err != nil {
		return nil, fmt.Errorf("getting algorithm details: %w", err)
	}

	privKey, err := cosign.GeneratePrivateKeyWithAlgorithm(&algo)
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}

	defaultLoadOptions = cosign.GetDefaultLoadOptions(defaultLoadOptions)
	sv, err := signature.LoadSignerVerifierFromAlgorithmDetails(privKey, algo, *defaultLoadOptions...)
	if err != nil {
		return nil, err
	}

	return &SignerVerifier{
		SignerVerifier: sv,
	}, nil
}

// GetRFC3161Timestamp fetches an RFC3161 timestamp as raw bytes and as a RFC3161Timestamp object.
// It either returns both objects to be assembled into a bundle by the calling function,
// or writes the formatted timestamp to the provided file path if not using the new bundle format.
func GetRFC3161Timestamp(payload []byte, ko options.KeyOpts) ([]byte, *cbundle.RFC3161Timestamp, error) {
	if ko.TSAServerURL == "" {
		return nil, nil, nil
	}
	if ko.RFC3161TimestampPath == "" && !ko.NewBundleFormat {
		return nil, nil, fmt.Errorf("expected either new bundle or an rfc3161-timestamp path when using a TSA server")
	}
	tc := client.NewTSAClient(ko.TSAServerURL)
	if ko.TSAClientCert != "" {
		tc = client.NewTSAClientMTLS(
			ko.TSAServerURL,
			ko.TSAClientCACert,
			ko.TSAClientCert,
			ko.TSAClientKey,
			ko.TSAServerName,
		)
	}
	timestampBytes, err := tsa.GetTimestampedSignature(payload, tc)
	if err != nil {
		return nil, nil, fmt.Errorf("getting timestamped signature: %w", err)
	}
	rfc3161Timestamp := cbundle.TimestampToRFC3161Timestamp(timestampBytes)
	if rfc3161Timestamp == nil {
		return nil, nil, fmt.Errorf("rfc3161 timestamp is nil")
	}
	if ko.NewBundleFormat || ko.RFC3161TimestampPath == "" {
		return timestampBytes, rfc3161Timestamp, nil
	}
	ts, err := json.Marshal(rfc3161Timestamp)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling timestamp: %w", err)
	}
	if err := os.WriteFile(ko.RFC3161TimestampPath, ts, 0600); err != nil {
		return nil, nil, fmt.Errorf("creating RFC3161 timestamp file: %w", err)
	}
	fmt.Fprintln(os.Stderr, "RFC3161 timestamp written to file ", ko.RFC3161TimestampPath)
	return timestampBytes, rfc3161Timestamp, nil
}

type tlogUploadFn func(*rekorclient.Rekor, []byte) (*models.LogEntryAnon, error)

// UploadToTlog uploads an entry to rekor v1 and returns the response from rekor.
func UploadToTlog(ctx context.Context, ko options.KeyOpts, ref name.Reference, tlogUpload bool, rekorBytes []byte, upload tlogUploadFn) (*models.LogEntryAnon, error) {
	shouldUpload, err := ShouldUploadToTlog(ctx, ko, ref, tlogUpload)
	if err != nil {
		return nil, fmt.Errorf("checking upload to tlog: %w", err)
	}
	if !shouldUpload {
		return nil, nil
	}
	rekorClient, err := rekor.NewClient(ko.RekorURL)
	if err != nil {
		return nil, fmt.Errorf("creating rekor client: %w", err)
	}
	entry, err := upload(rekorClient, rekorBytes)
	if err != nil {
		return nil, fmt.Errorf("uploading to rekor: %w", err)
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return entry, nil
}

type CommonBundleOpts struct {
	Payload       []byte
	Digest        name.Digest
	PredicateType string
	BundlePath    string
	Upload        bool
	OCIRemoteOpts []ociremote.Option
}

// WriteBundle compiles a protobuf bundle from components and writes the bundle to the OCI remote layer.
func WriteBundle(ctx context.Context, sv *SignerVerifier, rekorEntry *models.LogEntryAnon, bundleOpts CommonBundleOpts, signedPayload, signerBytes, timestampBytes []byte) error {
	pubKey, err := sv.PublicKey()
	if err != nil {
		return err
	}
	bundleBytes, err := cbundle.MakeNewBundle(pubKey, rekorEntry, bundleOpts.Payload, signedPayload, signerBytes, timestampBytes)
	if err != nil {
		return err
	}
	if bundleOpts.BundlePath != "" {
		if err := os.WriteFile(bundleOpts.BundlePath, bundleBytes, 0600); err != nil {
			return fmt.Errorf("creating bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", bundleOpts.BundlePath)
	}
	if !bundleOpts.Upload {
		return nil
	}
	return ociremote.WriteAttestationNewBundleFormat(bundleOpts.Digest, bundleBytes, bundleOpts.PredicateType, bundleOpts.OCIRemoteOpts...)
}

// WriteNewBundleWithSigningConfig uses signing config and trusted root to fetch responses from services for the bundle and writes the bundle to the OCI remote layer.
func WriteNewBundleWithSigningConfig(ctx context.Context, ko options.KeyOpts, cert, certChain string, bundleOpts CommonBundleOpts, signingConfig *root.SigningConfig, trustedMaterial root.TrustedMaterial) error {
	keypair, _, certBytes, idToken, err := GetKeypairAndToken(ctx, ko, cert, certChain)
	if err != nil {
		return fmt.Errorf("getting keypair and token: %w", err)
	}

	content := &sign.DSSEData{
		Data:        bundleOpts.Payload,
		PayloadType: "application/vnd.in-toto+json",
	}

	var tsaClientTransport http.RoundTripper
	if ko.TSAClientCACert != "" || (ko.TSAClientCert != "" && ko.TSAClientKey != "") {
		tsaClientTransport, err = client.GetHTTPTransport(ko.TSAClientCACert, ko.TSAClientCert, ko.TSAClientKey, ko.TSAServerName, 30*time.Second)
		if err != nil {
			return fmt.Errorf("getting TSA client transport: %w", err)
		}
	}
	signOpts := cbundle.SignOptions{TSAClientTransport: tsaClientTransport}

	bundle, err := cbundle.SignData(ctx, content, keypair, idToken, certBytes, signingConfig, trustedMaterial, signOpts)
	if err != nil {
		return fmt.Errorf("signing bundle: %w", err)
	}

	if bundleOpts.BundlePath != "" {
		if err := os.WriteFile(bundleOpts.BundlePath, bundle, 0600); err != nil {
			return fmt.Errorf("creating bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", bundleOpts.BundlePath)
		return nil
	}
	if !bundleOpts.Upload {
		return nil
	}
	return ociremote.WriteAttestationNewBundleFormat(bundleOpts.Digest, bundle, bundleOpts.PredicateType, bundleOpts.OCIRemoteOpts...)
}

type bundleComponents struct {
	SV               *SignerVerifier
	SignedPayload    []byte
	TimestampBytes   []byte
	RFC3161Timestamp *cbundle.RFC3161Timestamp
	SignerBytes      []byte
	RekorEntry       *models.LogEntryAnon
}

// GetBundleComponents fetches data needed to compose the bundle or disparate verification material for any signing command.
func GetBundleComponents(ctx context.Context, cert, certChain string, ko options.KeyOpts, noupload, tlogUpload bool, payload []byte, digest name.Reference, rekorEntryType string) (*bundleComponents, func(), error) { //nolint:revive
	bc := &bundleComponents{}
	var err error
	var closeSV func()
	bc.SV, closeSV, err = GetSignerVerifier(ctx, cert, certChain, ko)
	if err != nil {
		return nil, nil, fmt.Errorf("getting signer: %w", err)
	}
	wrapped := dsse.WrapSigner(bc.SV, types.IntotoPayloadType)

	bc.SignedPayload, err = wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		closeSV()
		return nil, nil, fmt.Errorf("signing: %w", err)
	}
	if noupload {
		return bc, closeSV, nil
	}
	// We need to decide what signature to send to the timestamp authority.
	//
	// Historically, cosign sent `signedPayload`, which is the entire JSON DSSE
	// Envelope. However, when sigstore clients are verifying a bundle they
	// will use the DSSE Sig field, so we choose what signature to send to
	// the timestamp authority based on our output format.
	tsaPayload := bc.SignedPayload
	if ko.NewBundleFormat {
		tsaPayload, err = cosign.GetDSSESigBytes(bc.SignedPayload)
		if err != nil {
			closeSV()
			return nil, nil, fmt.Errorf("getting DSSE signature: %w", err)
		}
	}
	bc.TimestampBytes, bc.RFC3161Timestamp, err = GetRFC3161Timestamp(tsaPayload, ko)
	if err != nil {
		closeSV()
		return nil, nil, fmt.Errorf("getting timestamp: %w", err)
	}
	bc.SignerBytes, err = bc.SV.Bytes(ctx)
	if err != nil {
		closeSV()
		return nil, nil, fmt.Errorf("converting signer to bytes: %w", err)
	}
	bc.RekorEntry, err = UploadToTlog(ctx, ko, digest, tlogUpload, bc.SignerBytes, func(r *rekorclient.Rekor, b []byte) (*models.LogEntryAnon, error) {
		if rekorEntryType == "intoto" {
			return cosign.TLogUploadInTotoAttestation(ctx, r, bc.SignedPayload, b)
		}
		return cosign.TLogUploadDSSEEnvelope(ctx, r, bc.SignedPayload, b)
	})
	if err != nil {
		closeSV()
		return nil, nil, fmt.Errorf("uploading to tlog: %w", err)
	}
	return bc, closeSV, nil
}

// ParseOCIReference parses a string reference to an OCI image into a reference, warning if the reference did not include a digest.
func ParseOCIReference(ctx context.Context, refStr string, opts ...name.Option) (name.Reference, error) {
	ref, err := name.ParseReference(refStr, opts...)
	if err != nil {
		return nil, fmt.Errorf("parsing reference: %w", err)
	}
	if _, ok := ref.(name.Digest); !ok {
		ui.Warnf(ctx, ui.TagReferenceMessage, refStr)
	}
	return ref, nil
}

func ParseSignatureAlgorithmFlag(signingAlgorithm string) (pb_go_v1.PublicKeyDetails, error) {
	if signingAlgorithm == "" {
		var err error
		signingAlgorithm, err = signature.FormatSignatureAlgorithmFlag(pb_go_v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
		if err != nil {
			return pb_go_v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, fmt.Errorf("formatting signature algorithm: %w", err)
		}
	}
	return signature.ParseSignatureAlgorithmFlag(signingAlgorithm)
}

// LoadTrustedMaterialAndSigningConfig loads the trusted material and signing config from the given options.
func LoadTrustedMaterialAndSigningConfig(ctx context.Context, ko *options.KeyOpts, useSigningConfig bool, signingConfigPath string,
	rekorURL, fulcioURL, oidcIssuer, tsaServerURL, trustedRootPath string,
	tlogUpload bool, newBundleFormat bool, bundlePath string, keyRef string, issueCertificate bool,
	output, outputAttestation, outputCertificate, outputPayload, outputSignature string) error {
	var err error
	// If a signing config is used, then service URLs cannot be specified
	if (useSigningConfig || signingConfigPath != "") &&
		((rekorURL != "" && rekorURL != options.DefaultRekorURL) ||
			(fulcioURL != "" && fulcioURL != options.DefaultFulcioURL) ||
			(oidcIssuer != "" && oidcIssuer != options.DefaultOIDCIssuerURL) ||
			tsaServerURL != "") {
		return fmt.Errorf("cannot specify service URLs and use signing config")
	}
	if (useSigningConfig || signingConfigPath != "") && !tlogUpload {
		return fmt.Errorf("--tlog-upload=false is not supported with --signing-config or --use-signing-config. Provide a signing config with --signing-config without a transparency log service, which can be created with `cosign signing-config create` or `curl https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | jq 'del(.rekorTlogUrls)'` for the public instance")
	}
	// Signing config requires a bundle as output for verification materials since sigstore-go is used
	if (useSigningConfig || signingConfigPath != "") && !newBundleFormat && bundlePath == "" {
		return fmt.Errorf("must provide --new-bundle-format or --bundle where applicable with --signing-config or --use-signing-config")
	}
	// Fetch a trusted root when:
	// * requesting a certificate and no CT log key is provided to verify an SCT
	// * using a signing config
	if ((keyRef == "" || issueCertificate) && env.Getenv(env.VariableSigstoreCTLogPublicKeyFile) == "") ||
		(useSigningConfig || signingConfigPath != "") {
		if trustedRootPath != "" {
			ko.TrustedMaterial, err = root.NewTrustedRootFromPath(trustedRootPath)
			if err != nil {
				return fmt.Errorf("loading trusted root: %w", err)
			}
		} else {
			ko.TrustedMaterial, err = cosign.TrustedRoot()
			if err != nil {
				ui.Warnf(ctx, "Could not fetch trusted_root.json from the TUF repository. Continuing with individual targets. Error from TUF: %v", err)
			}
		}
	}
	if signingConfigPath != "" {
		ko.SigningConfig, err = root.NewSigningConfigFromPath(signingConfigPath)
		if err != nil {
			return fmt.Errorf("error reading signing config from file: %w", err)
		}
	} else if useSigningConfig {
		ko.SigningConfig, err = cosign.SigningConfig()
		if err != nil {
			return fmt.Errorf("error getting signing config from TUF: %w", err)
		}
	}

	// TODO: Remove deprecated output flags warning in a future release (when flags are removed)
	if newBundleFormat && outputSignature != "" {
		ui.Warnf(context.Background(), "--output-signature is deprecated when using --new-bundle-format and will be ignored")
	}
	if newBundleFormat && outputAttestation != "" {
		ui.Warnf(context.Background(), "--output-attestation is deprecated when using --new-bundle-format and will be ignored")
	}
	if newBundleFormat && outputCertificate != "" {
		ui.Warnf(context.Background(), "--output-certificate is deprecated when using --new-bundle-format and will be ignored")
	}
	if newBundleFormat && outputPayload != "" {
		ui.Warnf(context.Background(), "--output-payload is deprecated when using --new-bundle-format and will be ignored")
	}
	if newBundleFormat && output != "" {
		ui.Warnf(context.Background(), "--output is deprecated when using --new-bundle-format and will be ignored")
	}

	return nil
}
