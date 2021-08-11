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

package attestation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
)

const (
	// CosignCustomProvenanceV01 specifies the type of the Predicate.
	CosignCustomProvenanceV01 = "cosign.sigstore.dev/attestation/v1"
)

// CosignPredicate specifies the format of the Custom Predicate.
type CosignPredicate struct {
	Data      string
	Timestamp string
}

// GenerateOpts specifies the options of the Statement generator.
type GenerateOpts struct {
	// Path is the given path to the predicate file.
	Path string
	// Type is the pre-defined enums (provenance|link|spdx).
	// default: custom
	Type string
	// Digest of the Image reference.
	Digest string
	// Repo context of the reference.
	Repo string

	// Function to return the time to set
	Time func() time.Time
}

// GenerateStatement returns corresponding Predicate (custom|provenance|spdx|link)
// based on the type you specified.
func GenerateStatement(opts GenerateOpts) (interface{}, error) {
	rawPayload, err := readPayload(opts.Path)
	if err != nil {
		return nil, err
	}
	switch opts.Type {
	case "custom":
		if opts.Time == nil {
			opts.Time = time.Now
		}
		now := opts.Time()
		stamp := now.UTC().Format(time.RFC3339)
		return generateCustomStatement(rawPayload, opts.Digest, opts.Repo, stamp)
	case "provenance":
		return generateProvenanceStatement(rawPayload, opts.Digest, opts.Repo)
	case "spdx":
		return generateSPDXStatement(rawPayload, opts.Digest, opts.Repo)
	case "link":
		return generateLinkStatement(rawPayload, opts.Digest, opts.Repo)
	default:
		return nil, errors.New(fmt.Sprintf("we don't know this predicate type: '%s'", opts.Type))
	}
}

func generateStatementHeader(digest, repo, predicateType string) in_toto.StatementHeader {
	return in_toto.StatementHeader{
		Type:          in_toto.StatementInTotoV01,
		PredicateType: predicateType,
		Subject: []in_toto.Subject{
			{
				Name: repo,
				Digest: map[string]string{
					"sha256": digest,
				},
			},
		},
	}
}

//
func generateCustomStatement(rawPayload []byte, digest, repo, timestamp string) (interface{}, error) {
	return in_toto.Statement{
		StatementHeader: generateStatementHeader(digest, repo, CosignCustomProvenanceV01),
		Predicate: CosignPredicate{
			Data:      string(rawPayload),
			Timestamp: timestamp,
		},
	}, nil
}

func generateProvenanceStatement(rawPayload []byte, digest string, repo string) (interface{}, error) {
	var predicate in_toto.ProvenancePredicate
	err := checkRequiredJSONFields(rawPayload, reflect.TypeOf(predicate))
	if err != nil {
		return nil, fmt.Errorf("provenance predicate: %v", err)
	}
	err = json.Unmarshal(rawPayload, &predicate)
	if err != nil {
		return "", errors.Wrap(err, "unmarshal Provenance predicate")
	}
	return in_toto.ProvenanceStatement{
		StatementHeader: generateStatementHeader(digest, repo, in_toto.PredicateProvenanceV01),
		Predicate:       predicate,
	}, nil
}

func generateLinkStatement(rawPayload []byte, digest string, repo string) (interface{}, error) {
	var link in_toto.Link
	err := checkRequiredJSONFields(rawPayload, reflect.TypeOf(link))
	if err != nil {
		return nil, fmt.Errorf("link statement: %v", err)
	}
	err = json.Unmarshal(rawPayload, &link)
	if err != nil {
		return "", errors.Wrap(err, "unmarshal Link statement")
	}
	return in_toto.LinkStatement{
		StatementHeader: generateStatementHeader(digest, repo, in_toto.PredicateLinkV1),
		Predicate:       link,
	}, nil
}

func generateSPDXStatement(rawPayload []byte, digest string, repo string) (interface{}, error) {
	return in_toto.SPDXStatement{
		StatementHeader: generateStatementHeader(digest, repo, in_toto.PredicateSPDX),
		Predicate: CosignPredicate{
			Data: string(rawPayload),
		},
	}, nil
}

func readPayload(predicatePath string) ([]byte, error) {
	rawPayload, err := ioutil.ReadFile(filepath.Clean(predicatePath))
	if err != nil {
		return nil, errors.Wrap(err, "payload from file")
	}
	return rawPayload, nil
}

func checkRequiredJSONFields(rawPayload []byte, typ reflect.Type) error {
	var tmp map[string]interface{}
	if err := json.Unmarshal(rawPayload, &tmp); err != nil {
		return err
	}
	// Create list of json tags, e.g. `json:"_type"`
	attributeCount := typ.NumField()
	allFields := make([]string, 0)
	for i := 0; i < attributeCount; i++ {
		jsonTagFields := strings.SplitN(typ.Field(i).Tag.Get("json"), ",", 2)
		if len(jsonTagFields) < 2 {
			allFields = append(allFields, jsonTagFields[0])
		}
	}

	// Assert that there's a key in the passed map for each tag
	for _, field := range allFields {
		if _, ok := tmp[field]; !ok {
			return fmt.Errorf("required field %s missing", field)
		}
	}
	return nil
}
