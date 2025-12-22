//
// Copyright 2024 The Sigstore Authors.
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

package trustedroot

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type CreateCmd struct {
	FulcioSpecs []string
	RekorSpecs  []string
	CTFESpecs   []string
	TSASpecs    []string

	WithDefaultServices bool
	NoDefaultFulcio     bool
	NoDefaultCTFE       bool
	NoDefaultTSA        bool
	NoDefaultRekor      bool

	// Deprecated flags
	CertChain        []string
	FulcioURI        []string
	CtfeKeyPath      []string
	CtfeStartTime    []string
	CtfeEndTime      []string
	CtfeURL          []string
	Out              string
	RekorKeyPath     []string
	RekorStartTime   []string
	RekorEndTime     []string
	RekorURL         []string
	TSACertChainPath []string
	TSAURI           []string
}

func (c *CreateCmd) Exec(_ context.Context) error {
	var fulcioCertAuthorities []root.CertificateAuthority
	ctLogs := make(map[string]*root.TransparencyLog)
	var timestampAuthorities []root.TimestampingAuthority
	rekorTransparencyLogs := make(map[string]*root.TransparencyLog)
	var err error

	// Decide whether to use new or old flags
	fulcioSpecUsed := len(c.FulcioSpecs) > 0
	deprecatedFulcioFlagsUsed := len(c.CertChain) > 0 || len(c.FulcioURI) > 0
	if fulcioSpecUsed && deprecatedFulcioFlagsUsed {
		return fmt.Errorf("cannot use --fulcio and old fulcio flags at the same time")
	}

	rekorSpecUsed := len(c.RekorSpecs) > 0
	deprecatedRekorFlagsUsed := len(c.RekorKeyPath) > 0 || len(c.RekorURL) > 0 || len(c.RekorStartTime) > 0 || len(c.RekorEndTime) > 0
	if rekorSpecUsed && deprecatedRekorFlagsUsed {
		return fmt.Errorf("cannot use --rekor and old rekor flags at the same time")
	}

	ctfeSpecUsed := len(c.CTFESpecs) > 0
	deprecatedCTFEFlagsUsed := len(c.CtfeKeyPath) > 0 || len(c.CtfeURL) > 0 || len(c.CtfeStartTime) > 0 || len(c.CtfeEndTime) > 0
	if ctfeSpecUsed && deprecatedCTFEFlagsUsed {
		return fmt.Errorf("cannot use --ctfe and old ctfe flags at the same time")
	}

	tsaSpecUsed := len(c.TSASpecs) > 0
	deprecatedTSAFlagsUsed := len(c.TSACertChainPath) > 0 || len(c.TSAURI) > 0
	if tsaSpecUsed && deprecatedTSAFlagsUsed {
		return fmt.Errorf("cannot use --tsa and old tsa flags at the same time")
	}

	if c.WithDefaultServices {
		tr, err := cosign.TrustedRoot()
		if err != nil {
			return fmt.Errorf("getting default trusted root: %w", err)
		}
		if !c.NoDefaultFulcio {
			fulcioCertAuthorities = append(fulcioCertAuthorities, tr.FulcioCertificateAuthorities()...)
		}
		if !c.NoDefaultCTFE {
			maps.Copy(ctLogs, tr.CTLogs())
		}
		if !c.NoDefaultRekor {
			maps.Copy(rekorTransparencyLogs, tr.RekorLogs())
		}
		if !c.NoDefaultTSA {
			timestampAuthorities = append(timestampAuthorities, tr.TimestampingAuthorities()...)
		}
	}

	if fulcioSpecUsed {
		for _, spec := range c.FulcioSpecs {
			fulcioAuthority, err := parseFulcioSpec(spec)
			if err != nil {
				return fmt.Errorf("parsing fulcio spec: %w", err)
			}
			fulcioCertAuthorities = append(fulcioCertAuthorities, fulcioAuthority)
		}
	} else if deprecatedFulcioFlagsUsed {
		for i := 0; i < len(c.CertChain); i++ {
			var fulcioURI string
			if i < len(c.FulcioURI) {
				fulcioURI = c.FulcioURI[i]
			}
			fulcioAuthority, err := parseCAPEMFile(c.CertChain[i], fulcioURI)
			if err != nil {
				return err
			}
			fulcioCertAuthorities = append(fulcioCertAuthorities, fulcioAuthority)
		}
	}

	if ctfeSpecUsed {
		for _, spec := range c.CTFESpecs {
			ctLog, id, err := parseTLogSpec(spec)
			if err != nil {
				return fmt.Errorf("parsing ctfe spec: %w", err)
			}
			ctLogs[id] = ctLog
		}
	} else if deprecatedCTFEFlagsUsed {
		for i := 0; i < len(c.CtfeKeyPath); i++ {
			ctLogPubKey, id, idBytes, err := getPubKey(c.CtfeKeyPath[i]) // #nosec G601
			if err != nil {
				return err
			}

			startTime := time.Unix(0, 0)
			endTime := time.Time{}

			if i < len(c.CtfeStartTime) { // #nosec G601
				startTime, err = time.Parse(time.RFC3339, c.CtfeStartTime[i])
				if err != nil {
					return err
				}
			}
			if i < len(c.CtfeEndTime) { // #nosec G601
				endTime, err = time.Parse(time.RFC3339, c.CtfeEndTime[i])
				if err != nil {
					return err
				}
			}

			ctLogs[id] = &root.TransparencyLog{
				HashFunc:            crypto.SHA256,
				ID:                  idBytes,
				ValidityPeriodStart: startTime,
				PublicKey:           ctLogPubKey,
				SignatureHashFunc:   getSignatureHashAlgo(ctLogPubKey),
			}

			if !endTime.IsZero() {
				ctLogs[id].ValidityPeriodEnd = endTime
			}

			if i < len(c.CtfeURL) { // #nosec G601
				ctLogs[id].BaseURL = c.CtfeURL[i]
			}
		}
	}

	if rekorSpecUsed {
		for _, spec := range c.RekorSpecs {
			rekorLog, id, err := parseTLogSpec(spec)
			if err != nil {
				return fmt.Errorf("parsing rekor spec: %w", err)
			}
			// Rekor v2 needs origin for checkpoint ID
			kvs, _ := parseKVs(spec)
			if origin, ok := kvs["origin"]; ok {
				id, rekorLog.ID, err = getCheckpointID(origin, rekorLog.PublicKey)
				if err != nil {
					return err
				}
			}
			rekorTransparencyLogs[id] = rekorLog
		}
	} else if deprecatedRekorFlagsUsed {
		for i := 0; i < len(c.RekorKeyPath); i++ {
			keyParts := strings.SplitN(c.RekorKeyPath[i], ",", 2) // #nosec G601
			keyPath := keyParts[0]
			tlogPubKey, id, idBytes, err := getPubKey(keyPath)
			if err != nil {
				return err
			}
			var origin string
			if len(keyParts) > 1 {
				origin = keyParts[1]
			}
			if origin != "" {
				id, idBytes, err = getCheckpointID(origin, tlogPubKey)
				if err != nil {
					return err
				}
			}

			startTime := time.Unix(0, 0)
			endTime := time.Time{}

			if i < len(c.RekorStartTime) { // #nosec G601
				startTime, err = time.Parse(time.RFC3339, c.RekorStartTime[i])
				if err != nil {
					return err
				}
			}
			if i < len(c.RekorEndTime) { // #nosec G601
				endTime, err = time.Parse(time.RFC3339, c.RekorEndTime[i])
				if err != nil {
					return err
				}
			}

			rekorTransparencyLogs[id] = &root.TransparencyLog{
				HashFunc:            crypto.SHA256,
				ID:                  idBytes,
				ValidityPeriodStart: startTime,
				PublicKey:           tlogPubKey,
				SignatureHashFunc:   getSignatureHashAlgo(tlogPubKey),
			}
			if !endTime.IsZero() {
				rekorTransparencyLogs[id].ValidityPeriodEnd = endTime
			}

			if i < len(c.RekorURL) { // #nosec G601
				rekorTransparencyLogs[id].BaseURL = c.RekorURL[i]
			}
		}
	}

	if tsaSpecUsed {
		for _, spec := range c.TSASpecs {
			tsa, err := parseTSASpec(spec)
			if err != nil {
				return fmt.Errorf("parsing tsa spec: %w", err)
			}
			timestampAuthorities = append(timestampAuthorities, tsa)
		}
	} else if deprecatedTSAFlagsUsed {
		for i := 0; i < len(c.TSACertChainPath); i++ {
			var tsaURI string // #nosec G601
			if i < len(c.TSAURI) {
				tsaURI = c.TSAURI[i]
			}
			timestampAuthority, err := parseTAPEMFile(c.TSACertChainPath[i], tsaURI)
			if err != nil {
				return err
			}
			timestampAuthorities = append(timestampAuthorities, timestampAuthority)
		}
	}

	newTrustedRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		fulcioCertAuthorities, ctLogs, timestampAuthorities,
		rekorTransparencyLogs,
	)
	if err != nil {
		return err
	}

	var trBytes []byte

	trBytes, err = newTrustedRoot.MarshalJSON()
	if err != nil {
		return err
	}

	if c.Out != "" {
		err = os.WriteFile(c.Out, trBytes, 0600)
		if err != nil {
			return err
		}
	} else {
		fmt.Println(string(trBytes))
	}

	return nil
}

func parseCAPEMFile(path, uri string) (root.CertificateAuthority, error) {
	certs, err := parseCerts(path)
	if err != nil {
		return nil, err
	}

	var ca root.FulcioCertificateAuthority
	ca.Root = certs[len(certs)-1]
	ca.ValidityPeriodStart = certs[len(certs)-1].NotBefore
	if len(certs) > 1 {
		ca.Intermediates = certs[:len(certs)-1]
	}
	ca.URI = uri

	return &ca, nil
}

func parseTAPEMFile(path, uri string) (root.TimestampingAuthority, error) {
	certs, err := parseCerts(path)
	if err != nil {
		return nil, err
	}

	if certs[0].IsCA {
		return nil, fmt.Errorf("first certificate in chain must be a leaf certificate")
	}
	if len(certs) < 2 {
		return nil, fmt.Errorf("certificate chain must have at least two certificates")
	}

	rootCert := certs[len(certs)-1]
	var intermediates []*x509.Certificate
	leafCert := certs[0]

	if len(certs) > 1 {
		intermediates = certs[1 : len(certs)-1]
	}

	return &root.SigstoreTimestampingAuthority{
		Root:                rootCert,
		Intermediates:       intermediates,
		Leaf:                leafCert,
		ValidityPeriodStart: rootCert.NotBefore,
		URI:                 uri,
	}, nil
}

func parseCerts(path string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for block, contents := pem.Decode(contents); block != nil; block, contents = pem.Decode(contents) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)

		if len(contents) == 0 {
			break
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in file %s", path)
	}

	return certs, nil
}

func getPubKey(path string) (crypto.PublicKey, string, []byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, "", []byte{}, err
	}

	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, "", []byte{}, err
	}

	keyID, err := cosign.GetTransparencyLogID(pubKey)
	if err != nil {
		return nil, "", []byte{}, err
	}

	idBytes, err := hex.DecodeString(keyID)
	if err != nil {
		return nil, "", []byte{}, err
	}

	return pubKey, keyID, idBytes, nil
}

func getCheckpointID(origin string, key crypto.PublicKey) (string, []byte, error) {
	_, id, err := note.KeyHash(origin, key)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(id), id, nil
}

func parseKVs(spec string) (map[string]string, error) {
	kvs := make(map[string]string)
	pairs := strings.Split(spec, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", pair)
		}
		kvs[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return kvs, nil
}

func parseFulcioSpec(spec string) (root.CertificateAuthority, error) {
	kvs, err := parseKVs(spec)
	if err != nil {
		return nil, err
	}

	requiredKeys := []string{"url", "certificate-chain"}
	for _, key := range requiredKeys {
		if val, ok := kvs[key]; !ok || val == "" {
			return nil, fmt.Errorf("missing or empty required key '%s' in fulcio spec", key)
		}
	}

	certs, err := parseCerts(kvs["certificate-chain"])
	if err != nil {
		return nil, fmt.Errorf("parsing Fulcio certificate-chain: %w", err)
	}

	rootCert := certs[len(certs)-1]
	var intermediates []*x509.Certificate
	if len(certs) > 1 {
		intermediates = certs[:len(certs)-1]
	}

	startTime := rootCert.NotBefore
	if st, ok := kvs["start-time"]; ok && st != "" {
		startTime, err = time.Parse(time.RFC3339, st)
		if err != nil {
			return nil, fmt.Errorf("parsing start-time: %w", err)
		}
	}

	var endTime time.Time
	if et, ok := kvs["end-time"]; ok && et != "" {
		endTime, err = time.Parse(time.RFC3339, et)
		if err != nil {
			return nil, fmt.Errorf("parsing end-time: %w", err)
		}
	}

	return &root.FulcioCertificateAuthority{
		Root:                rootCert,
		Intermediates:       intermediates,
		ValidityPeriodStart: startTime,
		ValidityPeriodEnd:   endTime,
		URI:                 kvs["url"],
	}, nil
}

func parseTSASpec(spec string) (root.TimestampingAuthority, error) {
	kvs, err := parseKVs(spec)
	if err != nil {
		return nil, err
	}

	requiredKeys := []string{"url", "certificate-chain"}
	for _, key := range requiredKeys {
		if val, ok := kvs[key]; !ok || val == "" {
			return nil, fmt.Errorf("missing or empty required key '%s' in tsa spec", key)
		}
	}

	certs, err := parseCerts(kvs["certificate-chain"])
	if err != nil {
		return nil, fmt.Errorf("parsing TSA certificate-chain: %w", err)
	}
	if certs[0].IsCA {
		return nil, fmt.Errorf("first certificate in chain must be a leaf certificate")
	}

	leafCert := certs[0]
	rootCert := certs[len(certs)-1]
	var intermediates []*x509.Certificate
	if len(certs) > 1 {
		intermediates = certs[1 : len(certs)-1]
	}

	startTime := leafCert.NotBefore
	if st, ok := kvs["start-time"]; ok && st != "" {
		startTime, err = time.Parse(time.RFC3339, st)
		if err != nil {
			return nil, fmt.Errorf("parsing start-time: %w", err)
		}
	}

	var endTime time.Time
	if et, ok := kvs["end-time"]; ok && et != "" {
		endTime, err = time.Parse(time.RFC3339, et)
		if err != nil {
			return nil, fmt.Errorf("parsing end-time: %w", err)
		}
	}

	return &root.SigstoreTimestampingAuthority{
		Root:                rootCert,
		Intermediates:       intermediates,
		Leaf:                leafCert,
		ValidityPeriodStart: startTime,
		ValidityPeriodEnd:   endTime,
		URI:                 kvs["url"],
	}, nil
}

func parseTLogSpec(spec string) (*root.TransparencyLog, string, error) {
	kvs, err := parseKVs(spec)
	if err != nil {
		return nil, "", err
	}

	requiredKeys := []string{"url", "public-key", "start-time"}
	for _, key := range requiredKeys {
		if val, ok := kvs[key]; !ok || val == "" {
			return nil, "", fmt.Errorf("missing or empty required key '%s' in tlog spec", key)
		}
	}

	pubKey, id, idBytes, err := getPubKey(kvs["public-key"])
	if err != nil {
		return nil, "", fmt.Errorf("parsing public-key: %w", err)
	}

	startTime, err := time.Parse(time.RFC3339, kvs["start-time"])
	if err != nil {
		return nil, "", fmt.Errorf("parsing start-time: %w", err)
	}

	var endTime time.Time
	if et, ok := kvs["end-time"]; ok && et != "" {
		endTime, err = time.Parse(time.RFC3339, et)
		if err != nil {
			return nil, "", fmt.Errorf("parsing end-time: %w", err)
		}
	}

	tlog := &root.TransparencyLog{
		BaseURL:             kvs["url"],
		ID:                  idBytes,
		HashFunc:            crypto.SHA256,
		PublicKey:           pubKey,
		SignatureHashFunc:   getSignatureHashAlgo(pubKey),
		ValidityPeriodStart: startTime,
		ValidityPeriodEnd:   endTime,
	}
	return tlog, id, nil
}

func getSignatureHashAlgo(pubKey crypto.PublicKey) crypto.Hash {
	var h crypto.Hash
	switch pk := pubKey.(type) {
	case *rsa.PublicKey:
		h = crypto.SHA256
	case *ecdsa.PublicKey:
		switch pk.Curve {
		case elliptic.P256():
			h = crypto.SHA256
		case elliptic.P384():
			h = crypto.SHA384
		case elliptic.P521():
			h = crypto.SHA512
		default:
			h = crypto.SHA256
		}
	case ed25519.PublicKey:
		h = crypto.SHA512
	default:
		h = crypto.SHA256
	}
	return h
}
