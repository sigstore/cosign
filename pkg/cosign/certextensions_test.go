// Copyright 2022 The Sigstore Authors
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

package cosign

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func createCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte("myIssuer")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, Value: []byte("myWorkflowTrigger")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, Value: []byte("myWorkflowSha")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}, Value: []byte("myWorkflowName")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}, Value: []byte("myWorkflowRepository")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}, Value: []byte("myWorkflowRef")},
		},
	}
}

func TestCertExtensions(t *testing.T) {
	t.Parallel()
	cert := createCert(t)
	exts := CertExtensions{Cert: cert}

	if val := exts.GetIssuer(); val != "myIssuer" {
		t.Fatal("CertExtension does not extract field 'oidcIssuer' correctly")
	}

	if val := exts.GetCertExtensionGithubWorkflowTrigger(); val != "myWorkflowTrigger" {
		t.Fatal("CertExtension does not extract field 'githubWorkflowTrigger' correctly")
	}

	if val := exts.GetExtensionGithubWorkflowSha(); val != "myWorkflowSha" {
		t.Fatal("CertExtension does not extract field 'githubWorkflowSha' correctly")
	}

	if val := exts.GetCertExtensionGithubWorkflowName(); val != "myWorkflowName" {
		t.Fatal("CertExtension does not extract field 'githubWorkflowName' correctly")
	}

	if val := exts.GetCertExtensionGithubWorkflowRepository(); val != "myWorkflowRepository" {
		t.Fatal("CertExtension does not extract field 'githubWorkflowRepository' correctly")
	}

	if val := exts.GetCertExtensionGithubWorkflowRef(); val != "myWorkflowRef" {
		t.Fatal("CertExtension does not extract field 'githubWorkflowRef' correctly")
	}
}
