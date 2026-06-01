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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/blob"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	signature "github.com/sigstore/sigstore/pkg/signature"
)

var predicateTypeMap = map[string]string{
	"custom":           "https://cosign.sigstore.dev/attestation/v0.1",
	"slsaprovenance":   "https://slsa.dev/provenance/v0.2",
	"slsaprovenance02": "https://slsa.dev/provenance/v0.2",
	"slsaprovenance1":  "https://slsa.dev/provenance/v1",
	"spdx":             "https://spdx.dev/Document",
	"spdxjson":         "https://spdx.dev/Document",
	"cyclonedx":        "https://cyclonedx.org/bom",
	"link":             "https://in-toto.io/Link/v1",
	"vuln":             "https://cosign.sigstore.dev/attestation/vuln/v0.1",
	"openvex":          "https://openvex.dev/ns",
}

func verifyBundle(ctx context.Context, vo VerifyOpts, payloadPath string, isAttestation bool) error {
	bundle, err := sgbundle.LoadJSONFromPath(vo.BundlePath)
	if err != nil {
		return fmt.Errorf("loading bundle: %w", err)
	}

	co := &cosign.CheckOpts{
		IgnoreSCT:                    vo.IgnoreSCT,
		Offline:                      vo.Offline,
		IgnoreTlog:                   vo.IgnoreTlog,
		UseSignedTimestamps:          vo.UseSignedTimestamps,
		CertGithubWorkflowTrigger:    vo.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        vo.CertGithubWorkflowSha,
		CertGithubWorkflowName:       vo.CertGithubWorkflowName,
		CertGithubWorkflowRepository: vo.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        vo.CertGithubWorkflowRef,
		NewBundleFormat:              true,
	}

	if vo.KeyRef != "" {
		pubKeyBytes, err := blob.LoadFileOrURL(vo.KeyRef)
		if err != nil {
			return fmt.Errorf("reading public key file: %w", err)
		}

		block, _ := pem.Decode(pubKeyBytes)
		if block == nil {
			return errors.New("invalid public key PEM")
		}
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing public key: %w", err)
		}
		co.SigVerifier, err = signature.LoadVerifier(pubKey, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("loading verifier: %w", err)
		}
	}

	if vo.KeyRef == "" {
		if vo.CertIdentity == "" && vo.CertIdentityRegexp == "" {
			return errors.New("--certificate-identity or --certificate-identity-regexp is required for verification in keyless mode")
		}
		if vo.CertIdentityIssuer == "" && vo.CertIdentityIssuerRegexp == "" {
			return errors.New("--certificate-oidc-issuer or --certificate-oidc-issuer-regexp is required for verification in keyless mode")
		}
		co.Identities = []cosign.Identity{
			{
				Subject:       vo.CertIdentity,
				SubjectRegExp: vo.CertIdentityRegexp,
				Issuer:        vo.CertIdentityIssuer,
				IssuerRegExp:  vo.CertIdentityIssuerRegexp,
			},
		}
	}

	if vo.TrustedRootPath != "" {
		tr, err := sgroot.NewTrustedRootFromPath(vo.TrustedRootPath)
		if err != nil {
			return fmt.Errorf("loading custom trusted root: %w", err)
		}
		co.TrustedMaterial = tr
	} else {
		vOfflineKey := vo.KeyRef != "" && co.IgnoreTlog && !co.UseSignedTimestamps
		if !vOfflineKey {
			var err error
			co.TrustedMaterial, err = cosign.TrustedRoot()
			if err != nil {
				return fmt.Errorf("loading TUF trusted root: %w", err)
			}
		}
	}

	var policyOpt sgverify.ArtifactPolicyOption
	if isAttestation {
		switch {
		case !vo.CheckClaims:
			policyOpt = sgverify.WithoutArtifactUnsafe()
		case payloadPath != "":
			if isDigest(payloadPath) {
				alg, digest, err := parsePayloadDigest(payloadPath)
				if err != nil {
					return err
				}
				policyOpt = sgverify.WithArtifactDigest(alg, digest)
			} else {
				r, closeR, err := getArtifactReader(payloadPath)
				if err != nil {
					return err
				}
				defer func() { _ = closeR() }()
				policyOpt = sgverify.WithArtifact(r)
			}
		default:
			return errors.New("must provide payload file or specify --check-claims=false")
		}
	} else {
		if payloadPath == "" {
			return errors.New("missing payload file argument")
		}
		if isDigest(payloadPath) {
			alg, digest, err := parsePayloadDigest(payloadPath)
			if err != nil {
				return err
			}
			policyOpt = sgverify.WithArtifactDigest(alg, digest)
		} else {
			r, closeR, err := getArtifactReader(payloadPath)
			if err != nil {
				return err
			}
			defer func() { _ = closeR() }()
			policyOpt = sgverify.WithArtifact(r)
		}
	}

	_, err = cosign.VerifyNewBundle(ctx, co, policyOpt, bundle)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	if isAttestation {
		sigContent, err := bundle.SignatureContent()
		if err != nil {
			return fmt.Errorf("extracting signature content: %w", err)
		}
		envContent := sigContent.EnvelopeContent()
		if envContent == nil {
			return errors.New("bundle does not contain a DSSE envelope")
		}
		rawEnv := envContent.RawEnvelope()
		if rawEnv == nil {
			return errors.New("bundle does not contain a raw DSSE envelope")
		}

		payloadBytes, err := json.Marshal(rawEnv)
		if err != nil {
			return fmt.Errorf("marshaling envelope: %w", err)
		}

		b, gotPredicateType, err := attestationToPayloadJSON(ctx, vo.PredicateType, payloadBytes)
		if err != nil {
			return fmt.Errorf("verifying policy statement: %w", err)
		}
		if b == nil {
			return fmt.Errorf("predicate type mismatch: expected %s, got %s", vo.PredicateType, gotPredicateType)
		}
	}

	ui.Infof(ctx, "Verified OK")

	return nil
}

func getArtifactReader(payloadPath string) (io.Reader, func() error, error) {
	if payloadPath == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	f, err := os.Open(filepath.Clean(payloadPath))
	if err != nil {
		return nil, nil, fmt.Errorf("opening payload file: %w", err)
	}
	return f, f.Close, nil
}

func attestationToPayloadJSON(_ context.Context, predicateType string, payloadBytes []byte) ([]byte, string, error) {
	if predicateType == "" {
		return nil, "", errors.New("missing predicate type")
	}
	predicateURI, ok := predicateTypeMap[predicateType]
	if !ok {
		predicateURI = predicateType
	}

	var payloadData map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payloadData); err != nil {
		return nil, "", fmt.Errorf("unmarshaling payload data: %w", err)
	}

	val, ok := payloadData["payload"]
	if !ok {
		return nil, "", fmt.Errorf("could not find payload field in payload data")
	}
	payloadStr, ok := val.(string)
	if !ok {
		return nil, "", fmt.Errorf("invalid payload: payload field is not a string (got %T)", val)
	}
	decodedPayload, err := base64.StdEncoding.DecodeString(payloadStr)
	if err != nil {
		return nil, "", fmt.Errorf("decoding payload: %w", err)
	}

	var statement struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(decodedPayload, &statement); err != nil {
		return nil, "", fmt.Errorf("unmarshaling in-toto statement: %w", err)
	}

	if statement.PredicateType != predicateURI {
		return nil, statement.PredicateType, nil
	}

	return decodedPayload, statement.PredicateType, nil
}

func parsePayloadDigest(blobRef string) (string, []byte, error) {
	hexAlg, hexDigest, ok := strings.Cut(blobRef, ":")
	if !ok {
		return "", nil, fmt.Errorf("invalid digest format: %s", blobRef)
	}
	digestBytes, err := hex.DecodeString(hexDigest)
	if err != nil {
		return "", nil, fmt.Errorf("decoding hex digest: %w", err)
	}
	return hexAlg, digestBytes, nil
}

func isDigest(blobRef string) bool {
	if _, err := os.Stat(blobRef); err == nil {
		return false
	}
	return strings.Contains(blobRef, ":")
}
