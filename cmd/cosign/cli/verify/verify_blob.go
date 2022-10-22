//
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

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-openapi/runtime"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/tuf"

	ctypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/intoto"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/rekord"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// nolint
func VerifyBlobCmd(ctx context.Context, ko options.KeyOpts, certRef, certEmail, certIdentity,
	certOidcIssuer, certChain, sigRef, blobRef, certGithubWorkflowTrigger, certGithubWorkflowSha,
	certGithubWorkflowName,
	certGithubWorkflowRepository,
	certGithubWorkflowRef string, enforceSCT bool) error {
	var cert *x509.Certificate
	var bundle *bundle.RekorBundle

	if !options.OneOf(ko.KeyRef, ko.Sk, certRef) && !options.EnableExperimental() && ko.BundlePath == "" {
		return &options.PubKeyParseError{}
	}

	sig, err := signatures(sigRef, ko.BundlePath)
	if err != nil {
		return err
	}

	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		return err
	}

	co := &cosign.CheckOpts{
		CertEmail:                    certEmail,
		CertIdentity:                 certIdentity,
		CertOidcIssuer:               certOidcIssuer,
		CertGithubWorkflowTrigger:    certGithubWorkflowTrigger,
		CertGithubWorkflowSha:        certGithubWorkflowSha,
		CertGithubWorkflowName:       certGithubWorkflowName,
		CertGithubWorkflowRepository: certGithubWorkflowRepository,
		CertGithubWorkflowRef:        certGithubWorkflowRef,
		EnforceSCT:                   enforceSCT,
	}
	if options.EnableExperimental() {
		if ko.RekorURL != "" {
			rekorClient, err := rekor.NewClient(ko.RekorURL)
			if err != nil {
				return fmt.Errorf("creating Rekor client: %w", err)
			}
			co.RekorClient = rekorClient
		}
	}
	if options.EnableExperimental() {
		co.RootCerts, err = fulcio.GetRoots()
		if err != nil {
			return fmt.Errorf("getting Fulcio roots: %w", err)
		}
		co.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
	}

	// Keys are optional!
	switch {
	case ko.KeyRef != "":
		co.SigVerifier, err = sigs.PublicKeyFromKeyRef(ctx, ko.KeyRef)
		if err != nil {
			return fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case ko.Sk:
		sk, err := pivkey.GetKeyWithSlot(ko.Slot)
		if err != nil {
			return fmt.Errorf("opening piv token: %w", err)
		}
		defer sk.Close()
		co.SigVerifier, err = sk.Verifier()
		if err != nil {
			return fmt.Errorf("loading public key from token: %w", err)
		}
	case certRef != "":
		cert, err = loadCertFromFileOrURL(certRef)
		if err != nil {
			return err
		}
		if certChain == "" {
			co.RootCerts, err = fulcio.GetRoots()
			if err != nil {
				return fmt.Errorf("getting Fulcio roots: %w", err)
			}

			co.IntermediateCerts, err = fulcio.GetIntermediates()
			if err != nil {
				return fmt.Errorf("getting Fulcio intermediates: %w", err)
			}
			co.SigVerifier, err = cosign.ValidateAndUnpackCert(cert, co)
			if err != nil {
				return fmt.Errorf("validating certRef: %w", err)
			}
		} else {
			// Verify certificate with chain
			chain, err := loadCertChainFromFileOrURL(certChain)
			if err != nil {
				return err
			}
			co.SigVerifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
			if err != nil {
				return fmt.Errorf("verifying certRef with certChain: %w", err)
			}
		}
	case ko.BundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(ko.BundlePath)
		if err != nil {
			return err
		}
		if b.Cert == "" {
			return fmt.Errorf("bundle does not contain cert for verification, please provide public key")
		}
		// b.Cert can either be a certificate or public key
		certBytes := []byte(b.Cert)
		if isb64(certBytes) {
			certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
		}
		cert, err = loadCertFromPEM(certBytes)
		if err != nil {
			// check if cert is actually a public key
			co.SigVerifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
		} else {
			if certChain == "" {
				co.RootCerts, err = fulcio.GetRoots()
				if err != nil {
					return fmt.Errorf("getting Fulcio roots: %w", err)
				}
				co.IntermediateCerts, err = fulcio.GetIntermediates()
				if err != nil {
					return fmt.Errorf("getting Fulcio intermediates: %w", err)
				}
				co.SigVerifier, err = cosign.ValidateAndUnpackCert(cert, co)
				if err != nil {
					return fmt.Errorf("verifying certificate from bundle: %w", err)
				}
			} else {
				// Verify certificate with chain
				chain, err := loadCertChainFromFileOrURL(certChain)
				if err != nil {
					return err
				}
				co.SigVerifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
				if err != nil {
					return fmt.Errorf("verifying certificate from bundle with chain: %w", err)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("loading verifier from bundle: %w", err)
		}
		bundle = b.Bundle
	// No certificate is provided: search by artifact sha in the TLOG.
	case options.EnableExperimental():
		uuids, err := cosign.FindTLogEntriesByPayload(ctx, co.RekorClient, blobBytes)
		if err != nil {
			return err
		}

		if len(uuids) == 0 {
			return errors.New("could not find a tlog entry for provided blob")
		}

		// Iterate through and try to find a matching Rekor entry.
		// This does not support intoto properly! c/f extractCerts and
		// the verifier.
		for _, u := range uuids {
			tlogEntry, err := cosign.GetTlogEntry(ctx, co.RekorClient, u)
			if err != nil {
				continue
			}

			// Note that this will error out if the TLOG entry was signed with a
			// raw public key. Again, using search on artifact sha is unreliable.
			certs, err := extractCerts(tlogEntry)
			if err != nil {
				continue
			}

			cert := certs[0]
			co.SigVerifier, err = cosign.ValidateAndUnpackCert(cert, co)
			if err != nil {
				continue
			}

			if err := verifyBlob(ctx, co, blobBytes, sig, cert,
				nil, tlogEntry); err == nil {
				// We found a succesful Rekor entry!
				fmt.Fprintln(os.Stderr, "Verified OK")
				return nil
			}
		}

		// No successful Rekor entry found.
		fmt.Fprintln(os.Stderr, `WARNING: No valid entries were found in rekor to verify this blob.

Transparency log support for blobs is experimental, and occasionally an entry isn't found even if one exists.

We recommend requesting the certificate/signature from the original signer of this blob and manually verifying with cosign verify-blob --cert [cert] --signature [signature].`)
		return fmt.Errorf("could not find a valid tlog entry for provided blob, found %d invalid entries", len(uuids))

	}

	// Performs all blob verification.
	if err := verifyBlob(ctx, co, blobBytes, sig, cert, bundle, nil); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

/* Verify Blob main entry point. This will perform the following:
   1. Verifies the signature on the blob using the provided verifier.
   2. Checks for transparency log entry presence:
        a. Verifies the Rekor entry in the bundle, if provided. OR
        b. If we don't have a Rekor entry retrieved via cert, do an online lookup (assuming
           we are in experimental mode).
        c. Uses the provided Rekor entry (may have been retrieved through Rekor SearchIndex) OR
   3. If a certificate is provided, check it's expiration.
*/
// TODO: Make a version of this public. This could be VerifyBlobCmd, but we need to
// clean up the args into CheckOpts or use KeyOpts here to resolve different KeyOpts.
func verifyBlob(ctx context.Context, co *cosign.CheckOpts,
	blobBytes []byte, sig string, cert *x509.Certificate,
	bundle *bundle.RekorBundle, e *models.LogEntryAnon) error {
	if cert != nil {
		// This would have already be done in the main entrypoint, but do this for robustness.
		var err error
		co.SigVerifier, err = cosign.ValidateAndUnpackCert(cert, co)
		if err != nil {
			return fmt.Errorf("validating cert: %w", err)
		}
	}

	// Use the DSSE verifier if the payload is a DSSE with the In-Toto format.
	// TODO: This verifier only supports verification of a single signer/signature on
	// the envelope. Either have the verifier validate that only one signature exists,
	// or use a multi-signature verifier.
	if isIntotoDSSE(blobBytes) {
		co.SigVerifier = dsse.WrapVerifier(co.SigVerifier)
	}

	// 1. Verify the signature.
	if err := co.SigVerifier.VerifySignature(strings.NewReader(sig), bytes.NewReader(blobBytes)); err != nil {
		return err
	}

	// This is the signature creation time. Without a transparency log entry timestamp,
	// we can only use the current time as a bound.
	var validityTime time.Time
	// 2. Checks for transparency log entry presence:
	switch {
	// a. We have a local bundle.
	case bundle != nil:
		var svBytes []byte
		var err error
		if cert != nil {
			svBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
			if err != nil {
				return fmt.Errorf("marshalling cert: %w", err)
			}
		} else {
			svBytes, err = sigs.PublicKeyPem(co.SigVerifier, signatureoptions.WithContext(ctx))
			if err != nil {
				return fmt.Errorf("marshalling pubkey: %w", err)
			}
		}
		bundle, err := verifyRekorBundle(ctx, bundle, co.RekorClient, blobBytes, sig, svBytes)
		if err != nil {
			// Return when the provided bundle fails verification. (Do not fallback).
			return err
		}
		validityTime = time.Unix(bundle.IntegratedTime, 0)
		fmt.Fprintf(os.Stderr, "tlog entry verified offline\n")
	// b. We can make an online lookup to the transparency log since we don't have an entry.
	case co.RekorClient != nil && e == nil:
		var tlogFindErr error
		if cert == nil {
			pub, err := co.SigVerifier.PublicKey(co.PKOpts...)
			if err != nil {
				return err
			}
			e, tlogFindErr = tlogFindPublicKey(ctx, co.RekorClient, blobBytes, sig, pub)
		} else {
			e, tlogFindErr = tlogFindCertificate(ctx, co.RekorClient, blobBytes, sig, cert)
		}
		if tlogFindErr != nil {
			// TODO: Think about whether we should break here.
			// This is COSIGN_EXPERIMENTAL mode, but in the case where someone
			// provided a public key or still-valid cert,
			/// they don't need TLOG lookup for the timestamp.
			fmt.Fprintf(os.Stderr, "could not find entry in tlog: %s", tlogFindErr)
			return tlogFindErr
		}
		// Fallthrough here to verify the TLOG entry and compute the integrated time.
		fallthrough
	// We are provided a log entry, possibly from above, or search.
	case e != nil:
		if err := cosign.VerifyTLogEntry(ctx, co.RekorClient, e); err != nil {
			return err
		}

		uuid, err := cosign.ComputeLeafHash(e)
		if err != nil {
			return err
		}

		validityTime = time.Unix(*e.IntegratedTime, 0)
		fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %s index: %d\n", hex.EncodeToString(uuid), *e.LogIndex)
	// If we do not have access to a bundle, a Rekor entry, or the access to lookup,
	// then we can only use the current time as the signature creation time to verify
	// the signature was created when the certificate was valid.
	default:
		validityTime = time.Now()
	}

	// 3. If a certificate is provided, check it's expiration.
	if cert == nil {
		return nil
	}

	return cosign.CheckExpiry(cert, validityTime)
}

func tlogFindPublicKey(ctx context.Context, rekorClient *client.Rekor,
	blobBytes []byte, sig string, pub crypto.PublicKey) (*models.LogEntryAnon, error) {
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	if err != nil {
		return nil, err
	}
	return tlogFindEntry(ctx, rekorClient, blobBytes, sig, pemBytes)
}

func tlogFindCertificate(ctx context.Context, rekorClient *client.Rekor,
	blobBytes []byte, sig string, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	pemBytes, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}
	return tlogFindEntry(ctx, rekorClient, blobBytes, sig, pemBytes)
}

func tlogFindEntry(ctx context.Context, client *client.Rekor,
	blobBytes []byte, sig string, pem []byte) (*models.LogEntryAnon, error) {
	b64sig := base64.StdEncoding.EncodeToString([]byte(sig))
	tlogEntries, err := cosign.FindTlogEntry(ctx, client, b64sig, blobBytes, pem)
	if err != nil {
		return nil, err
	}
	if len(tlogEntries) == 0 {
		return nil, fmt.Errorf("no valid tlog entries found with proposed entry")
	}
	// Always return the earliest integrated entry. That
	// always suffices for verification of signature time.
	var earliestLogEntry models.LogEntryAnon
	var earliestLogEntryTime *time.Time
	// We'll always return a tlog entry because there's at least one entry in the log.
	for _, entry := range tlogEntries {
		entryTime := time.Unix(*entry.IntegratedTime, 0)
		if earliestLogEntryTime == nil || entryTime.Before(*earliestLogEntryTime) {
			earliestLogEntryTime = &entryTime
			earliestLogEntry = entry
		}
	}
	return &earliestLogEntry, nil
}

// signatures returns the raw signature
func signatures(sigRef string, bundlePath string) (string, error) {
	var targetSig []byte
	var err error
	switch {
	case sigRef != "":
		targetSig, err = blob.LoadFileOrURL(sigRef)
		if err != nil {
			if !os.IsNotExist(err) {
				// ignore if file does not exist, it can be a base64 encoded string as well
				return "", err
			}
			targetSig = []byte(sigRef)
		}
	case bundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
		if err != nil {
			return "", err
		}
		targetSig = []byte(b.Base64Signature)
	default:
		return "", fmt.Errorf("missing flag '--signature'")
	}

	var sig, b64sig string
	if isb64(targetSig) {
		b64sig = string(targetSig)
		sigBytes, _ := base64.StdEncoding.DecodeString(b64sig)
		sig = string(sigBytes)
	} else {
		sig = string(targetSig)
	}
	return sig, nil
}

func payloadBytes(blobRef string) ([]byte, error) {
	var blobBytes []byte
	var err error
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return nil, err
	}
	return blobBytes, nil
}

// TODO: RekorClient can be removed when SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY
// is removed.
func verifyRekorBundle(ctx context.Context, bundle *bundle.RekorBundle, rekorClient *client.Rekor,
	blobBytes []byte, sig string, pubKeyBytes []byte) (*bundle.RekorPayload, error) {
	if err := verifyBundleMatchesData(ctx, bundle, blobBytes, pubKeyBytes, []byte(sig)); err != nil {
		return nil, err
	}

	publicKeys, err := cosign.GetRekorPubs(ctx, rekorClient)
	if err != nil {
		return nil, fmt.Errorf("retrieving rekor public key: %w", err)
	}

	pubKey, ok := publicKeys[bundle.Payload.LogID]
	if !ok {
		return nil, errors.New("rekor log public key not found for payload")
	}
	err = cosign.VerifySET(bundle.Payload, bundle.SignedEntryTimestamp, pubKey.PubKey)
	if err != nil {
		return nil, err
	}
	if pubKey.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
	}

	return &bundle.Payload, nil
}

func verifyBundleMatchesData(ctx context.Context, bundle *bundle.RekorBundle, blobBytes, certBytes, sigBytes []byte) error {
	eimpl, kind, apiVersion, err := unmarshalEntryImpl(bundle.Payload.Body.(string))
	if err != nil {
		return err
	}

	targetImpl, err := reconstructCanonicalizedEntry(ctx, kind, apiVersion, blobBytes, certBytes, sigBytes)
	if err != nil {
		return fmt.Errorf("recontructing rekorEntry for bundle comparison: %w", err)
	}

	switch e := eimpl.(type) {
	case *rekord_v001.V001Entry:
		t := targetImpl.(*rekord_v001.V001Entry)
		data, err := e.RekordObj.Data.Content.MarshalText()
		if err != nil {
			return fmt.Errorf("invalid rekord data: %w", err)
		}
		tData, err := t.RekordObj.Data.Content.MarshalText()
		if err != nil {
			return fmt.Errorf("invalid rekord data: %w", err)
		}
		if !bytes.Equal(data, tData) {
			return fmt.Errorf("rekord data does not match blob")
		}
		if err := compareBase64Strings(e.RekordObj.Signature.Content.String(),
			t.RekordObj.Signature.Content.String()); err != nil {
			return fmt.Errorf("rekord signature does not match bundle %w", err)
		}
		if err := compareBase64Strings(e.RekordObj.Signature.PublicKey.Content.String(),
			t.RekordObj.Signature.PublicKey.Content.String()); err != nil {
			return fmt.Errorf("rekord public key does not match bundle")
		}
	case *hashedrekord_v001.V001Entry:
		t := targetImpl.(*hashedrekord_v001.V001Entry)
		if *e.HashedRekordObj.Data.Hash.Value != *t.HashedRekordObj.Data.Hash.Value {
			return fmt.Errorf("hashedRekord data does not match blob")
		}
		if err := compareBase64Strings(e.HashedRekordObj.Signature.Content.String(),
			t.HashedRekordObj.Signature.Content.String()); err != nil {
			return fmt.Errorf("hashedRekord signature does not match bundle %w", err)
		}
		if err := compareBase64Strings(e.HashedRekordObj.Signature.PublicKey.Content.String(),
			t.HashedRekordObj.Signature.PublicKey.Content.String()); err != nil {
			return fmt.Errorf("hashedRekord public key does not match bundle")
		}
	case *intoto_v001.V001Entry:
		t := targetImpl.(*intoto_v001.V001Entry)
		if *e.IntotoObj.Content.Hash.Value != *t.IntotoObj.Content.Hash.Value {
			return fmt.Errorf("intoto content hash does not match attestation")
		}
		if *e.IntotoObj.Content.PayloadHash.Value != *t.IntotoObj.Content.PayloadHash.Value {
			return fmt.Errorf("intoto payload hash does not match attestation")
		}
		if err := compareBase64Strings(e.IntotoObj.PublicKey.String(),
			t.IntotoObj.PublicKey.String()); err != nil {
			return fmt.Errorf("intoto public key does not match bundle")
		}
	default:
		return errors.New("unexpected tlog entry type")
	}
	return nil
}

func reconstructCanonicalizedEntry(ctx context.Context, kind, apiVersion string, blobBytes, certBytes, sigBytes []byte) (types.EntryImpl, error) {
	props := types.ArtifactProperties{
		PublicKeyBytes: [][]byte{certBytes},
		PKIFormat:      string(pki.X509),
	}
	switch kind {
	case rekord.KIND:
		props.ArtifactBytes = blobBytes
		props.SignatureBytes = sigBytes
	case hashedrekord.KIND:
		blobHash := sha256.Sum256(blobBytes)
		props.ArtifactHash = strings.ToLower(hex.EncodeToString(blobHash[:]))
		props.SignatureBytes = sigBytes
	case intoto.KIND:
		props.ArtifactBytes = blobBytes
	default:
		return nil, fmt.Errorf("unexpected entry kind: %s", kind)
	}
	proposedEntry, err := types.NewProposedEntry(ctx, kind, apiVersion, props)
	if err != nil {
		return nil, err
	}

	eimpl, err := types.CreateVersionedEntry(proposedEntry)
	if err != nil {
		return nil, err
	}

	can, err := types.CanonicalizeEntry(ctx, eimpl)
	if err != nil {
		return nil, err
	}
	proposedEntryCan, err := models.UnmarshalProposedEntry(bytes.NewReader(can), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err = types.UnmarshalEntry(proposedEntryCan)
	if err != nil {
		return nil, err
	}

	return eimpl, nil
}

// unmarshalEntryImpl decodes the base64-encoded entry to a specific entry type (types.EntryImpl).
func unmarshalEntryImpl(e string) (types.EntryImpl, string, string, error) {
	b, err := base64.StdEncoding.DecodeString(e)
	if err != nil {
		return nil, "", "", err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, "", "", err
	}

	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, "", "", err
	}
	return entry, pe.Kind(), entry.APIVersion(), nil
}

func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	eimpl, _, _, err := unmarshalEntryImpl(e.Body.(string))
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord_v001.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord_v001.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}

// isIntotoDSSE checks whether a payload is a Dead Simple Signing Envelope with the In-Toto format.
func isIntotoDSSE(blobBytes []byte) bool {
	DSSEenvelope := ssldsse.Envelope{}
	if err := json.Unmarshal(blobBytes, &DSSEenvelope); err != nil {
		return false
	}
	if DSSEenvelope.PayloadType != ctypes.IntotoPayloadType {
		return false
	}

	return true
}

// TODO: Use this function to compare bundle signatures in OCI.
func compareBase64Strings(got string, expected string) error {
	decodeFirst, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		return fmt.Errorf("decoding base64 string %s", got)
	}
	decodeSecond, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("decoding base64 string %s", expected)
	}
	if !bytes.Equal(decodeFirst, decodeSecond) {
		return fmt.Errorf("comparing base64 strings, expected %s, got %s", expected, got)
	}
	return nil
}
