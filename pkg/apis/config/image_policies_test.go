// Copyright 2022 The Sigstore Authors.
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

package config

import (
	"testing"

	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	. "knative.dev/pkg/configmap/testing"
	_ "knative.dev/pkg/system/testing"
)

const (
	// Just some public key that was laying around, only format matters.
	inlineKeyData = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J
RCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==
-----END PUBLIC KEY-----`
)

func TestDefaultsConfigurationFromFile(t *testing.T) {
	_, example := ConfigMapsFromTestFile(t, ImagePoliciesConfigName)
	if _, err := NewImagePoliciesConfigFromConfigMap(example); err != nil {
		t.Error("NewImagePoliciesConfigFromConfigMap(example) =", err)
	}
}

func TestGetAuthorities(t *testing.T) {
	_, example := ConfigMapsFromTestFile(t, ImagePoliciesConfigName)
	defaults, err := NewImagePoliciesConfigFromConfigMap(example)
	if err != nil {
		t.Error("NewImagePoliciesConfigFromConfigMap(example) =", err)
	}
	c, err := defaults.GetMatchingPolicies("rando")
	checkGetMatches(t, c, err)
	matchedPolicy := "cluster-image-policy-0"
	want := "inlinedata here"
	if got := c[matchedPolicy][0].Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	// Make sure glob matches 'randomstuff*'
	c, err = defaults.GetMatchingPolicies("randomstuffhere")
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-1"
	want = "otherinline here"
	if got := c[matchedPolicy][0].Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	c, err = defaults.GetMatchingPolicies("rando3")
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-2"
	want = "cacert chilling here"
	if got := c[matchedPolicy][0].Keyless.CACert.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	want = "issuer"
	if got := c[matchedPolicy][0].Keyless.Identities[0].Issuer; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	want = "subject"
	if got := c[matchedPolicy][0].Keyless.Identities[0].Subject; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	// Make sure regex matches ".*regexstring.*"
	c, err = defaults.GetMatchingPolicies("randomregexstringstuff")
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-4"
	want = inlineKeyData
	if got := c[matchedPolicy][0].Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}

	// Test multiline yaml cert
	c, err = defaults.GetMatchingPolicies("inlinecert")
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-3"
	want = inlineKeyData
	if got := c[matchedPolicy][0].Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	// Test multiline cert but json encoded
	c, err = defaults.GetMatchingPolicies("ghcr.io/example/*")
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-json"
	want = inlineKeyData
	if got := c[matchedPolicy][0].Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	// Test multiple matches
	c, err = defaults.GetMatchingPolicies("regexstringtoo")
	checkGetMatches(t, c, err)
	if len(c) != 2 {
		t.Errorf("Wanted two matches, got %d", len(c))
	}
	matchedPolicy = "cluster-image-policy-4"
	want = inlineKeyData
	if got := c[matchedPolicy][0].Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	matchedPolicy = "cluster-image-policy-5"
	want = "inlinedata here"
	if got := c[matchedPolicy][0].Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
}

func checkGetMatches(t *testing.T, c map[string][]v1alpha1.Authority, err error) {
	t.Helper()
	if err != nil {
		t.Error("GetMatches Failed =", err)
	}
	if len(c) == 0 {
		t.Error("Wanted a config, got none.")
	}
	for _, v := range c {
		if v != nil || len(v) > 0 {
			return
		}
	}
	t.Error("Wanted a config and non-zero authorities, got no authorities")
}
