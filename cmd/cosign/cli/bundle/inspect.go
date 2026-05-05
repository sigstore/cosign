//
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

package bundle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/google/certificate-transparency-go/x509util"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	rekorv1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/util"
	"google.golang.org/protobuf/encoding/protojson"
)

type InspectCmd struct {
	BundlePath string
	Out        io.Writer
}

func (c *InspectCmd) Exec() error {
	fmt.Fprintln(os.Stderr, "WARNING: This command only inspects the contents of the bundle.")
	fmt.Fprintln(os.Stderr, "It does not perform cryptographic verification or check against the transparency log.")
	fmt.Fprintln(os.Stderr, "")

	f, err := os.Open(c.BundlePath)
	if err != nil {
		return fmt.Errorf("opening bundle file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("reading bundle: %w", err)
	}

	var b protobundle.Bundle
	err = protojson.Unmarshal(data, &b)
	if err != nil {
		return fmt.Errorf("unmarshaling bundle JSON: %w", err)
	}

	root := &node{}

	root.addChild("Bundle Media Type", b.MediaType)
	version, ok := recognizedMediaTypes[b.MediaType]
	if b.MediaType == "" {
		root.addChild("[!] WARNING", "Missing Bundle Media Type")
	} else if !ok {
		root.addChild("[!] WARNING", "Unrecognized Media Type")
	}

	if b.VerificationMaterial != nil {
		vmNode := root.addChild("Verification Material", "")

		switch content := b.VerificationMaterial.Content.(type) {
		case *protobundle.VerificationMaterial_Certificate:
			certNode := vmNode.addChild("Content", "X.509 Certificate")
			if len(content.Certificate.RawBytes) > 0 {
				populateCertificateSummary(certNode, content.Certificate.RawBytes)
			} else {
				certNode.addChild("[!] WARNING", "Certificate raw_bytes is empty")
			}

			if version > 0 && version < 3 {
				certNode.addChild("[!] WARNING", "v0.1/v0.2 bundle should use certificate chain, not single certificate")
			}

		case *protobundle.VerificationMaterial_X509CertificateChain:
			chainNode := vmNode.addChild("Content", "X.509 Certificate Chain")
			if len(content.X509CertificateChain.Certificates) > 0 {
				chainNode.addChild("Certificates", fmt.Sprintf("%d", len(content.X509CertificateChain.Certificates)))
				for i, cert := range content.X509CertificateChain.Certificates {
					certNode := chainNode.addChild(fmt.Sprintf("Certificate [%d]", i), "")
					populateCertificateSummary(certNode, cert.RawBytes)
				}
			} else {
				chainNode.addChild("[!] WARNING", "Certificate chain is empty")
			}

			if version >= 3 {
				chainNode.addChild("[!] WARNING", "v0.3 bundle should use single certificate, not chain")
			}

		case *protobundle.VerificationMaterial_PublicKey:
			pkNode := vmNode.addChild("Content", "Public Key Identifier")
			hint := content.PublicKey.GetHint()
			if hint != "" {
				if decoded, err := base64.StdEncoding.DecodeString(hint); err == nil {
					pkNode.addChild("Hint", hex.EncodeToString(decoded))
				} else {
					pkNode.addChild("Hint", hint)
				}
			} else {
				pkNode.addChild("[!] WARNING", "Public key hint is empty")
			}

		case nil:
			vmNode.addChild("[!] WARNING", "Missing Verification Material Content (must be certificate, chain, or public key)")
		}

		if len(b.VerificationMaterial.TlogEntries) > 0 {
			tlogNode := vmNode.addChild("Tlog Entries", fmt.Sprintf("%d", len(b.VerificationMaterial.TlogEntries)))
			for i, entry := range b.VerificationMaterial.TlogEntries {
				entryNode := tlogNode.addChild(fmt.Sprintf("Entry [%d]", i), "")
				populateTlogEntrySummary(entryNode, entry)

				if version == 1 && entry.GetInclusionPromise() == nil {
					entryNode.addChild("[!] WARNING", "v0.1 bundle tlog entry MUST contain an inclusion promise")
				}

				if version >= 2 && entry.GetInclusionProof() == nil {
					entryNode.addChild("[!] WARNING", fmt.Sprintf("v0.%d bundle tlog entry MUST contain an inclusion proof", version))
				}
			}
		}

		tsData := b.VerificationMaterial.TimestampVerificationData
		if tsData != nil {
			tsNode := vmNode.addChild("Timestamp Verification Data", "")
			populateTimestampSummary(tsNode, tsData)
		}
	} else {
		root.addChild("[!] WARNING", "Missing Verification Material")
	}

	if b.Content != nil {
		populateContentSummary(root, &b)
	} else {
		root.addChild("[!] WARNING", "Missing Content")
	}

	out := c.Out
	if out == nil {
		out = os.Stdout
	}
	root.print(out, 0)

	return nil
}

func populateCertificateSummary(n *node, rawBytes []byte) {
	cert, err := x509.ParseCertificate(rawBytes)
	if err != nil {
		n.addChild("Error", fmt.Sprintf("parsing certificate: %v", err))
		return
	}

	n.addChild("Signature Algorithm", cert.SignatureAlgorithm.String())

	if cert.Subject.String() != "" {
		n.addChild("Subject", cert.Subject.String())
	}

	hasIssuer := cert.Issuer.CommonName != "" || len(cert.Issuer.Organization) > 0 || len(cert.Issuer.Country) > 0
	if hasIssuer {
		issuerNode := n.addChild("Issuer", "")
		if cert.Issuer.CommonName != "" {
			issuerNode.addChild("Common Name", cert.Issuer.CommonName)
		}
		if len(cert.Issuer.Organization) > 0 {
			issuerNode.addChild("Organization", cert.Issuer.Organization[0])
		}
		if len(cert.Issuer.Country) > 0 {
			issuerNode.addChild("Country", cert.Issuer.Country[0])
		}
	}

	validityNode := n.addChild("Validity", "")
	validityNode.addChild("Not Before", cert.NotBefore.Format(time.RFC3339))
	validityNode.addChild("Not After", cert.NotAfter.Format(time.RFC3339))

	spkiNode := n.addChild("Subject Public Key Info", "")
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		spkiNode.addChild("Algorithm", "ECDSA")
		spkiNode.addChild("Curve", pub.Curve.Params().Name)
		if ecdhPub, err := pub.ECDH(); err == nil {
			pubBytes := ecdhPub.Bytes()
			pubHex := hex.EncodeToString(pubBytes)
			if len(pubHex) > 20 {
				spkiNode.addChild("Public Key", fmt.Sprintf("%s...%s (%d bytes)", pubHex[:8], pubHex[len(pubHex)-8:], len(pubBytes)))
			} else {
				spkiNode.addChild("Public Key", pubHex)
			}
		} else {
			spkiNode.addChild("Public Key", fmt.Sprintf("Error extracting key: %v", err))
		}

	case ed25519.PublicKey:
		spkiNode.addChild("Algorithm", "Ed25519")
		pubHex := hex.EncodeToString(pub)
		if len(pubHex) > 20 {
			spkiNode.addChild("Public Key", fmt.Sprintf("%s...%s (%d bytes)", pubHex[:8], pubHex[len(pubHex)-8:], len(pub)))
		} else {
			spkiNode.addChild("Public Key", pubHex)
		}

	case *rsa.PublicKey:
		spkiNode.addChild("Algorithm", "RSA")
		spkiNode.addChild("Key Size", fmt.Sprintf("%d bits", pub.N.BitLen()))

	default:
		spkiNode.addChild("Algorithm", "Unknown")
	}

	extsNode := n.addChild("Extensions", "")

	if cert.Subject.CommonName != "" || len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		identityNode := extsNode.addChild("Identity (Subject Alternative Name)", "")
		if cert.Subject.CommonName != "" {
			identityNode.addChild("Common Name", cert.Subject.CommonName)
		}
		for _, email := range cert.EmailAddresses {
			identityNode.addChild("Email", email)
		}
		for _, uri := range cert.URIs {
			identityNode.addChild("URI", uri.String())
		}
	}

	var usages []string
	for _, ku := range keyUsageNames {
		if cert.KeyUsage&ku.usage != 0 {
			usages = append(usages, ku.name)
		}
	}
	if len(usages) > 0 {
		extsNode.addChild("Key Usage", strings.Join(usages, ", "))
	}

	var extUsages []string
	for _, u := range cert.ExtKeyUsage {
		if name, ok := extKeyUsageNames[u]; ok {
			extUsages = append(extUsages, name)
		}
	}
	if len(extUsages) > 0 {
		extsNode.addChild("Extended Key Usage", strings.Join(extUsages, ", "))
	}

	var unknownExtUsages []string
	for _, u := range cert.UnknownExtKeyUsage {
		unknownExtUsages = append(unknownExtUsages, u.String())
	}
	if len(unknownExtUsages) > 0 {
		extsNode.addChild("Unknown Extended Key Usage", strings.Join(unknownExtUsages, ", "))
	}

	if len(cert.SubjectKeyId) > 0 {
		extsNode.addChild("Subject Key ID", hex.EncodeToString(cert.SubjectKeyId))
	}
	if len(cert.AuthorityKeyId) > 0 {
		keyID := hex.EncodeToString(cert.AuthorityKeyId)
		switch keyID {
		case fulcioProdIntermediateCAKeyID:
			extsNode.addChild("Authority", "Sigstore Intermediate Certificate Authority")
		case fulcioStagingIntermediateCAKeyID:
			extsNode.addChild("Authority", "Sigstore Intermediate Certificate Authority (Staging)")
		default:
			extsNode.addChild("Authority Key ID", keyID)
		}
	}

	// Other Extensions
	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		if handledOIDs[oidStr] {
			continue
		}

		if oidStr == sctExtensionOid {
			embeddedSCTs, err := x509util.ParseSCTsFromCertificate(cert.Raw)
			if err == nil && len(embeddedSCTs) > 0 {
				sctsNode := extsNode.addChild("Signed Certificate Timestamps", fmt.Sprintf("%d", len(embeddedSCTs)))
				for i, sct := range embeddedSCTs {
					sctNode := sctsNode.addChild(fmt.Sprintf("Signed Certificate Timestamp [%d]", i), "")
					sctNode.addChild("Version", fmt.Sprintf("v%d", sct.SCTVersion+1))

					logID := hex.EncodeToString(sct.LogID.KeyID[:])
					switch logID {
					case fulcioProdCTLogID:
						sctNode.addChild("Log", "Sigstore Certificate Transparency Log")
					case fulcioStagingCTLogID:
						sctNode.addChild("Log", "Sigstore Certificate Transparency Log (Staging)")
					default:
						sctNode.addChild("Log ID", logID)
					}

					sctNode.addChild("Timestamp", time.Unix(0, int64(sct.Timestamp)*1000000).Format(time.RFC3339))

					extStr := "none"
					if len(sct.Extensions) > 0 {
						extStr = fmt.Sprintf("%d bytes", len(sct.Extensions))
					}
					sctNode.addChild("Extensions", extStr)

					sctNode.addChild("Signature", fmt.Sprintf("Present (%d bytes)", len(sct.Signature.Signature)))
				}
				continue
			}
		}

		if readableName, ok := certExtensionMap[oidStr]; ok {
			valStr := string(ext.Value)
			var decodedStr string
			_, err := asn1.Unmarshal(ext.Value, &decodedStr)
			if err == nil {
				valStr = decodedStr
			}
			extsNode.addChild(readableName, valStr)
		} else {
			extsNode.addChild(fmt.Sprintf("OID: %s", oidStr), fmt.Sprintf("(Critical: %t) [%d bytes]", ext.Critical, len(ext.Value)))
		}
	}

	n.addChild("Signature", fmt.Sprintf("Present (%d bytes)", len(cert.Signature)))
}

func populateTlogEntrySummary(n *node, entry *rekorv1.TransparencyLogEntry) {
	n.addChild("Log Index", fmt.Sprintf("%d", entry.LogIndex))

	if entry.LogId != nil {
		logID := hex.EncodeToString(entry.LogId.KeyId)
		switch logID {
		case rekorV1ProdLogID:
			n.addChild("Log", "Rekor v1")
		case rekorV1StagingLogID:
			n.addChild("Log", "Rekor v1 (Staging)")
		case rekorV2ProdLogID:
			n.addChild("Log", "Rekor v2")
		case rekorV2StagingLogID:
			n.addChild("Log", "Rekor v2 (Staging)")
		default:
			n.addChild("Log ID", logID)
		}
	}

	if entry.KindVersion != nil {
		n.addChild("Kind", entry.KindVersion.Kind)
		n.addChild("Version", entry.KindVersion.Version)
	}

	if entry.IntegratedTime == 0 {
		n.addChild("Integrated Time", "0 (Not set)")
	} else {
		t := time.Unix(entry.IntegratedTime, 0).UTC()
		n.addChild("Integrated Time", t.Format(time.RFC3339))
	}

	if entry.GetInclusionPromise() != nil {
		promise := entry.GetInclusionPromise()
		promiseNode := n.addChild("Inclusion Promise", "")
		promiseNode.addChild("Signed Entry Timestamp", fmt.Sprintf("Present (%d bytes)", len(promise.SignedEntryTimestamp)))
	}

	if entry.GetInclusionProof() != nil {
		proof := entry.GetInclusionProof()
		proofNode := n.addChild("Inclusion Proof", "")
		proofNode.addChild("Log Index", fmt.Sprintf("%d", proof.LogIndex))
		proofNode.addChild("Tree Size", fmt.Sprintf("%d", proof.TreeSize))
		proofNode.addChild("Hashes", fmt.Sprintf("%d", len(proof.Hashes)))

		if proof.Checkpoint != nil {
			checkpointNode := proofNode.addChild("Checkpoint", "")
			var sc util.SignedCheckpoint
			if err := sc.UnmarshalText([]byte(proof.Checkpoint.Envelope)); err == nil {
				checkpointNode.addChild("Origin", sc.Origin)
				checkpointNode.addChild("Tree Size", fmt.Sprintf("%d", sc.Size))

				if len(sc.OtherContent) > 0 {
					otherNode := checkpointNode.addChild("Other Content", fmt.Sprintf("%d lines", len(sc.OtherContent)))
					for i, line := range sc.OtherContent {
						otherNode.addChild(fmt.Sprintf("[%d]", i), line)
					}
				}

				if len(sc.Signatures) > 0 {
					witnessesNode := checkpointNode.addChild("Witnesses", fmt.Sprintf("%d", len(sc.Signatures)))
					for _, sig := range sc.Signatures {
						sigBytes, err := base64.StdEncoding.DecodeString(sig.Base64)
						sigNode := witnessesNode.addChild(sig.Name, fmt.Sprintf("Signature Present (%d bytes)", len(sigBytes)))
						if err != nil {
							sigNode.addChild("[!] WARNING", "Malformed Base64")
						}
					}
				}
			} else {
				checkpointNode.addChild("Envelope", fmt.Sprintf("Present (%d bytes)", len(proof.Checkpoint.Envelope)))
			}
		}
	}

	if len(entry.CanonicalizedBody) > 0 {
		n.addChild("Canonicalized Body", fmt.Sprintf("Present (%d bytes)", len(entry.CanonicalizedBody)))
	}
}

func populateTimestampSummary(n *node, tsData *protobundle.TimestampVerificationData) {
	n.addChild("RFC3161 Timestamps", fmt.Sprintf("%d", len(tsData.GetRfc3161Timestamps())))
	for i, ts := range tsData.GetRfc3161Timestamps() {
		singleTsNode := n.addChild(fmt.Sprintf("Timestamp [%d]", i), "")

		var resp timeStampResp
		if _, err := asn1.Unmarshal(ts.SignedTimestamp, &resp); err == nil {
			if parsedTs, err := timestamp.Parse(resp.TimeStampToken.FullBytes); err == nil {
				singleTsNode.addChild("Time", parsedTs.Time.Format(time.RFC3339))
				singleTsNode.addChild("Hash Algorithm", parsedTs.HashAlgorithm.String())
				singleTsNode.addChild("Message Imprint", fmt.Sprintf("Present (%d bytes)", len(parsedTs.HashedMessage)))
				singleTsNode.addChild("Serial Number", fmt.Sprintf("%s", parsedTs.SerialNumber))
				singleTsNode.addChild("Policy", parsedTs.Policy.String())
			}
		}
	}
}

func populateContentSummary(n *node, b *protobundle.Bundle) {
	contentNode := n.addChild("Content", "")
	switch content := b.Content.(type) {
	case *protobundle.Bundle_DsseEnvelope:
		contentNode.addChild("Type", "DSSE Envelope")
		contentNode.addChild("Payload Type", content.DsseEnvelope.PayloadType)
		contentNode.addChild("Payload", fmt.Sprintf("Present (%d bytes)", len(content.DsseEnvelope.Payload)))

		if content.DsseEnvelope.PayloadType == "application/vnd.in-toto+json" {
			var statement map[string]interface{}
			if err := json.Unmarshal(content.DsseEnvelope.Payload, &statement); err == nil {
				payloadNode := contentNode.addChild("Payload Content (in-toto)", "")
				if predicateType, ok := statement["predicateType"].(string); ok {
					payloadNode.addChild("Predicate Type", predicateType)
				}
				if subjects, ok := statement["subject"].([]interface{}); ok {
					subjectsNode := payloadNode.addChild("Subjects", fmt.Sprintf("%d", len(subjects)))
					for _, s := range subjects {
						if subMap, ok := s.(map[string]interface{}); ok {
							if name, ok := subMap["name"].(string); ok {
								subjectsNode.addChild("Name", name)
							}
						}
					}
				}
			}
		}

		sigsNode := contentNode.addChild("Signatures", fmt.Sprintf("%d", len(content.DsseEnvelope.Signatures)))
		if len(content.DsseEnvelope.Signatures) != 1 {
			contentNode.addChild("[!] WARNING", "DSSE envelope MUST contain only one signature")
		}

		for i, sig := range content.DsseEnvelope.Signatures {
			sigNode := sigsNode.addChild(fmt.Sprintf("Signature [%d]", i), "")
			sigNode.addChild("Signature", fmt.Sprintf("Present (%d bytes)", len(sig.Sig)))
			if sig.Keyid != "" {
				if decoded, err := base64.StdEncoding.DecodeString(sig.Keyid); err == nil {
					sigNode.addChild("Key Hint", hex.EncodeToString(decoded))
				} else {
					sigNode.addChild("Key Hint", sig.Keyid)
				}

				if b.VerificationMaterial != nil && b.VerificationMaterial.GetPublicKey() != nil {
					vmHint := b.VerificationMaterial.GetPublicKey().GetHint()
					if vmHint != sig.Keyid {
						sigNode.addChild("[!] WARNING", "Key hint mismatch with Verification Material")
					}
				}
			}
		}

	case *protobundle.Bundle_MessageSignature:
		contentNode.addChild("Type", "Message Signature")
		if content.MessageSignature.MessageDigest != nil {
			digestNode := contentNode.addChild("Message Digest", "")
			digestNode.addChild("Algorithm", content.MessageSignature.MessageDigest.Algorithm.String())
			digestNode.addChild("Digest", fmt.Sprintf("Present (%d bytes)", len(content.MessageSignature.MessageDigest.Digest)))
		}
		contentNode.addChild("Signature", fmt.Sprintf("Present (%d bytes)", len(content.MessageSignature.Signature)))
	}
}

type pkiStatusInfo struct {
	Status int
	Rest   []asn1.RawValue `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type node struct {
	Label    string
	Value    string
	Children []node
}

func (n *node) addChild(label, value string) *node {
	n.Children = append(n.Children, node{Label: label, Value: value})
	return &n.Children[len(n.Children)-1]
}

func (n *node) print(w io.Writer, depth int) {
	if n.Label != "" {
		indent := strings.Repeat("  ", depth)
		if n.Value != "" {
			fmt.Fprintf(w, "%s- %s: %s\n", indent, n.Label, n.Value)
		} else {
			fmt.Fprintf(w, "%s- %s:\n", indent, n.Label)
		}
		depth++
	}
	for _, child := range n.Children {
		child.print(w, depth)
	}
}

// OIDs that are explicitly handled earlier in certificate population
// and should be skipped in the "Other Extensions" loop
var handledOIDs = map[string]bool{
	"2.5.29.15": true, // Key Usage
	"2.5.29.37": true, // Extended Key Usage
	"2.5.29.14": true, // Subject Key Identifier
	"2.5.29.35": true, // Authority Key Identifier
	"2.5.29.17": true, // Subject Alternative Name
}

var keyUsageNames = []struct {
	usage x509.KeyUsage
	name  string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Cert Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:             "Any",
	x509.ExtKeyUsageServerAuth:      "Server Auth",
	x509.ExtKeyUsageClientAuth:      "Client Auth",
	x509.ExtKeyUsageCodeSigning:     "Code Signing",
	x509.ExtKeyUsageEmailProtection: "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:  "IPSEC End System",
	x509.ExtKeyUsageIPSECTunnel:     "IPSEC Tunnel",
	x509.ExtKeyUsageIPSECUser:       "IPSEC User",
	x509.ExtKeyUsageTimeStamping:    "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSP Signing",
}

// Fulcio cert-extensions, documented here: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
var certExtensionMap = map[string]string{
	"1.3.6.1.4.1.57264.1.1":  "OIDC Issuer",
	"1.3.6.1.4.1.57264.1.2":  "GitHub Workflow Trigger",
	"1.3.6.1.4.1.57264.1.3":  "GitHub Workflow SHA",
	"1.3.6.1.4.1.57264.1.4":  "GitHub Workflow Name",
	"1.3.6.1.4.1.57264.1.5":  "GitHub Workflow Repository",
	"1.3.6.1.4.1.57264.1.6":  "GitHub Workflow Ref",
	"1.3.6.1.4.1.57264.1.7":  "OtherName SAN",
	"1.3.6.1.4.1.57264.1.8":  "Issuer (V2)",
	"1.3.6.1.4.1.57264.1.9":  "Build Signer URI",
	"1.3.6.1.4.1.57264.1.10": "Build Signer Digest",
	"1.3.6.1.4.1.57264.1.11": "Runner Environment",
	"1.3.6.1.4.1.57264.1.12": "Source Repository URI",
	"1.3.6.1.4.1.57264.1.13": "Source Repository Digest",
	"1.3.6.1.4.1.57264.1.14": "Source Repository Ref",
	"1.3.6.1.4.1.57264.1.15": "Source Repository Identifier",
	"1.3.6.1.4.1.57264.1.16": "Source Repository Owner URI",
	"1.3.6.1.4.1.57264.1.17": "Source Repository Owner Identifier",
	"1.3.6.1.4.1.57264.1.18": "Build Config URI",
	"1.3.6.1.4.1.57264.1.19": "Build Config Digest",
	"1.3.6.1.4.1.57264.1.20": "Build Trigger",
	"1.3.6.1.4.1.57264.1.21": "Run Invocation URI",
	"1.3.6.1.4.1.57264.1.22": "Source Repository Visibility At Signing",
	"1.3.6.1.4.1.57264.1.23": "Deployment Environment",
	"1.3.6.1.4.1.57264.1.24": "Token Subject",
}

const sctExtensionOid = "1.3.6.1.4.1.11129.2.4.2"

var recognizedMediaTypes = map[string]int{
	"application/vnd.dev.sigstore.bundle+json;version=0.1": 1,
	"application/vnd.dev.sigstore.bundle+json;version=0.2": 2,
	"application/vnd.dev.sigstore.bundle+json;version=0.3": 3,
	"application/vnd.dev.sigstore.bundle.v0.3+json":        3,
}

const fulcioProdIntermediateCAKeyID = "dfd3e9cf56241196f9a8d8e92855a2c62e18643f"
const fulcioStagingIntermediateCAKeyID = "718630a6147c626ff9f7d6f4051a7f5fffeb6fac"

// TODO: Add old Fulcio?

const fulcioProdCTLogID = "dd3d306ac6c7113263191e1c99673702a24a5eb8de3cadff878a72802f29ee8e"
const fulcioStagingCTLogID = "2b30bcdc6888c9e2e1d826295e741f4839319602f29c33cb5e4340feb2ac867a"

// TODO: Add old CT log (/test)?

const rekorV1ProdLogID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
const rekorV1StagingLogID = "d32f30a3c32d639c2b762205a21c7bb07788e68283a4ae6f42118723a1bea496"
const rekorV2ProdLogID = "08b6b33d643c241b7596e9216f47ddfdd9ecc53c02e3ec78834eeab33760c559"
const rekorV2StagingLogID = "d3d3a70ca130eff8696626153e84d1cd16e0947934b3296c528bde8274549496"

// TODO: Add retired Rekor v2 shards?
