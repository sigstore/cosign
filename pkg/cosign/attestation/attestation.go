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
	"io"
	"reflect"
	"strings"
	"time"

	slsa02_attest "github.com/in-toto/attestation/go/predicates/provenance/v02"
	slsa1_attest "github.com/in-toto/attestation/go/predicates/provenance/v1"
	in_toto_attest "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// CosignCustomProvenanceV01 specifies the type of the Predicate.
	CosignCustomProvenanceV01 = "https://cosign.sigstore.dev/attestation/v1"

	// CosignVulnProvenanceV01 specifies the type of VulnerabilityScan Predicate
	CosignVulnProvenanceV01 = "https://cosign.sigstore.dev/attestation/vuln/v1"

	// OpenVexNamespace holds the URI of the OpenVEX context to identify its
	// predicate type. More info about the specification can be found at
	// https://github.com/openvex/spec and the attestation spec is found here:
	// https://github.com/openvex/spec/blob/main/ATTESTING.md
	OpenVexNamespace = "https://openvex.dev/ns"
)

type Statement struct {
	*in_toto_attest.Statement
	// Catch legacy string predicates to preserve exact byte marshaling
	LegacyPredicate *string `json:"-"`
}

func (s *Statement) MarshalJSON() ([]byte, error) {
	if s.LegacyPredicate == nil {
		return protojson.Marshal(s.Statement)
	}
	legacyStatement := map[string]any{
		"_type":         s.Type,
		"subject":       s.Subject,
		"predicateType": s.PredicateType,
		"predicate":     s.LegacyPredicate,
	}
	return json.Marshal(legacyStatement)
}

func (s *Statement) UnmarshalJSON(stBytes []byte) error {
	st := in_toto_attest.Statement{}
	if err := protojson.Unmarshal(stBytes, &st); err == nil {
		s.Statement = &st
		return nil
	}

	// The predicate might be a string instead of a JSON object, which the in-toto library can't parse.
	// Convert it to a JSON object and try again.
	stmtMap := make(map[string]any)
	if err := json.Unmarshal(stBytes, &stmtMap); err != nil {
		return err
	}
	predicate, ok := stmtMap["predicate"]
	if !ok {
		return fmt.Errorf("could not parse statement, could not find predicate")
	}
	p, ok := predicate.(string)
	if !ok {
		return fmt.Errorf("could not parse predicate with type %T", predicate)
	}
	s.LegacyPredicate = &p
	delete(stmtMap, "predicate")
	remarshaled, err := json.Marshal(stmtMap)
	if err != nil {
		return fmt.Errorf("failed to marshal statement: %w", err)
	}
	return json.Unmarshal(remarshaled, &s.Statement)
}

// CosignPredicate specifies the format of the Custom Predicate.
type CosignPredicate struct {
	Data      interface{}
	Timestamp string
}

// VulnPredicate specifies the format of the Vulnerability Scan Predicate
type CosignVulnPredicate struct {
	Invocation Invocation `json:"invocation"`
	Scanner    Scanner    `json:"scanner"`
	Metadata   Metadata   `json:"metadata"`
}

// I think this will be moving to upstream in-toto in the fullness of time
// but creating it here for now so that we have a way to deserialize it
// as a InToto Statement
// https://github.com/in-toto/attestation/issues/58
type CosignVulnStatement struct {
	Type          string                               `json:"type,omitempty"`
	Subject       []*in_toto_attest.ResourceDescriptor `json:"subject,omitempty"`
	PredicateType string                               `json:"predicateType,omitempty"`
	Predicate     CosignVulnPredicate                  `json:"predicate"`
}

type Invocation struct {
	Parameters interface{} `json:"parameters"`
	URI        string      `json:"uri"`
	EventID    string      `json:"event_id"`
	BuilderID  string      `json:"builder.id"`
}

type DB struct {
	URI     string `json:"uri"`
	Version string `json:"version"`
}

type Scanner struct {
	URI     string      `json:"uri"`
	Version string      `json:"version"`
	DB      DB          `json:"db"`
	Result  interface{} `json:"result"`
}

type Metadata struct {
	ScanStartedOn  time.Time `json:"scanStartedOn"`
	ScanFinishedOn time.Time `json:"scanFinishedOn"`
}

// GenerateOpts specifies the options of the Statement generator.
type GenerateOpts struct {
	// Predicate is the source of bytes (e.g. a file) to use as the statement's predicate.
	Predicate io.Reader
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

// GenerateStatement returns an in-toto statement based on the provided
// predicate type (custom|slsaprovenance|slsaprovenance02|slsaprovenance1|spdx|spdxjson|cyclonedx|link).
func GenerateStatement(opts GenerateOpts) (*Statement, error) {
	predicate, err := io.ReadAll(opts.Predicate)
	if err != nil {
		return nil, err
	}

	switch opts.Type {
	case "slsaprovenance":
		return generateSLSAProvenanceStatementSLSA02(predicate, opts.Digest, opts.Repo)
	case "slsaprovenance02":
		return generateSLSAProvenanceStatementSLSA02(predicate, opts.Digest, opts.Repo)
	case "slsaprovenance1":
		return generateSLSAProvenanceStatementSLSA1(predicate, opts.Digest, opts.Repo)
	case "spdx":
		return generateSPDXStatement(predicate, opts.Digest, opts.Repo, false)
	case "spdxjson":
		return generateSPDXStatement(predicate, opts.Digest, opts.Repo, true)
	case "cyclonedx":
		return generateCycloneDXStatement(predicate, opts.Digest, opts.Repo)
	case "link":
		return generateLinkStatement(predicate, opts.Digest, opts.Repo)
	case "vuln":
		return generateVulnStatement(predicate, opts.Digest, opts.Repo)
	case "openvex":
		return generateOpenVexStatement(predicate, opts.Digest, opts.Repo)
	default:
		stamp := timestamp(opts)
		predicateType := customType(opts)
		return generateCustomStatement(predicate, predicateType, opts.Digest, opts.Repo, stamp)
	}
}

func generateVulnStatement(predicate []byte, digest string, repo string) (*Statement, error) {
	var vuln CosignVulnPredicate

	err := json.Unmarshal(predicate, &vuln)
	if err != nil {
		return nil, err
	}

	vulnObj, err := structToStruct(vuln)
	if err != nil {
		return nil, err
	}

	return &Statement{
		Statement: &in_toto_attest.Statement{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: CosignVulnProvenanceV01,
			Subject: []*in_toto_attest.ResourceDescriptor{
				{
					Name: repo,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
			Predicate: vulnObj,
		}}, nil
}

func timestamp(opts GenerateOpts) string {
	if opts.Time == nil {
		opts.Time = time.Now
	}
	now := opts.Time()
	return now.UTC().Format(time.RFC3339)
}

func customType(opts GenerateOpts) string {
	if opts.Type != "custom" {
		return opts.Type
	}
	return CosignCustomProvenanceV01
}

func generateCustomStatement(rawPayload []byte, customType, digest, repo, timestamp string) (*Statement, error) {
	payload, err := generateCustomPredicate(rawPayload, customType, timestamp)
	if err != nil {
		return nil, err
	}

	predicate, err := structpb.NewStruct(payload)
	if err != nil {
		return nil, err
	}

	return &Statement{
		Statement: &in_toto_attest.Statement{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: customType,
			Subject: []*in_toto_attest.ResourceDescriptor{
				{
					Name: repo,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
			Predicate: predicate,
		}}, nil
}

func generateCustomPredicate(rawPayload []byte, customType, timestamp string) (map[string]any, error) {
	if customType == CosignCustomProvenanceV01 {
		return map[string]any{
			"Data":      string(rawPayload),
			"Timestamp": timestamp,
		}, nil
	}

	var result map[string]any
	if err := json.Unmarshal(rawPayload, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON payload for predicate type %s: %w", customType, err)
	}

	return result, nil
}

func generateSLSAProvenanceStatementSLSA02(rawPayload []byte, digest string, repo string) (*Statement, error) {
	var predicate slsa02_attest.Provenance
	err := checkRequiredJSONFields(rawPayload, reflect.TypeOf(predicate.ProtoReflect().Interface()))
	if err != nil {
		return nil, fmt.Errorf("provenance predicate: %w", err)
	}
	protoOpts := protojson.UnmarshalOptions{DiscardUnknown: true}
	err = protoOpts.Unmarshal(rawPayload, &predicate)
	if err != nil {
		return nil, fmt.Errorf("unmarshal Provenance predicate: %w", err)
	}
	predicateObj, err := protoStructToStruct(&predicate)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Statement: &in_toto_attest.Statement{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: slsa02.PredicateSLSAProvenance,
			Subject: []*in_toto_attest.ResourceDescriptor{
				{
					Name: repo,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
			Predicate: predicateObj,
		}}, nil
}

func generateSLSAProvenanceStatementSLSA1(rawPayload []byte, digest string, repo string) (*Statement, error) {
	var genericPredicate map[string]any
	if err := json.Unmarshal(rawPayload, &genericPredicate); err != nil {
		return nil, fmt.Errorf("unmarshal raw payload to map: %w", err)
	}

	// Safely rename the key if it exists
	if runDetails, ok := genericPredicate["runDetails"].(map[string]any); ok {
		if metadata, ok := runDetails["metadata"].(map[string]any); ok {
			if val, exists := metadata["invocationID"]; exists {
				metadata["invocationId"] = val
				delete(metadata, "invocationID")
			}
		}
	}

	modifiedPayload, err := json.Marshal(genericPredicate)
	if err != nil {
		return nil, fmt.Errorf("marshal modified payload: %w", err)
	}

	var predicate slsa1_attest.Provenance
	err = checkRequiredJSONFields(modifiedPayload, reflect.TypeOf(predicate.ProtoReflect().Interface()))
	if err != nil {
		return nil, fmt.Errorf("provenance predicate: %w", err)
	}
	protoOpts := protojson.UnmarshalOptions{DiscardUnknown: true}
	err = protoOpts.Unmarshal(modifiedPayload, &predicate)
	if err != nil {
		return nil, fmt.Errorf("unmarshal Provenance predicate: %w", err)
	}
	predicateObj, err := protoStructToStruct(&predicate)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Statement: &in_toto_attest.Statement{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: slsa1.PredicateSLSAProvenance,
			Subject: []*in_toto_attest.ResourceDescriptor{
				{
					Name: repo,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
			Predicate: predicateObj,
		}}, nil
}

func generateLinkStatement(rawPayload []byte, digest string, repo string) (*Statement, error) {
	var link in_toto.Link
	err := checkRequiredJSONFields(rawPayload, reflect.TypeOf(link))
	if err != nil {
		return nil, fmt.Errorf("link statement: %w", err)
	}
	err = json.Unmarshal(rawPayload, &link)
	if err != nil {
		return nil, fmt.Errorf("unmarshal Link statement: %w", err)
	}
	linkObj, err := structToStruct(link)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Statement: &in_toto_attest.Statement{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: in_toto.PredicateLinkV1,
			Subject: []*in_toto_attest.ResourceDescriptor{
				{
					Name: repo,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
			Predicate: linkObj,
		}}, nil
}

func generateOpenVexStatement(rawPayload []byte, digest string, repo string) (*Statement, error) {
	var data map[string]any
	if err := json.Unmarshal(rawPayload, &data); err != nil {
		return nil, err
	}
	dataObj, err := structpb.NewStruct(data)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Statement: &in_toto_attest.Statement{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: OpenVexNamespace,
			Subject: []*in_toto_attest.ResourceDescriptor{
				{
					Name: repo,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
			Predicate: dataObj,
		}}, nil
}

func generateSPDXStatement(rawPayload []byte, digest string, repo string, parseJSON bool) (*Statement, error) {
	stmt := &in_toto_attest.Statement{
		Type:          in_toto.StatementInTotoV01,
		PredicateType: in_toto.PredicateSPDX,
		Subject: []*in_toto_attest.ResourceDescriptor{
			{
				Name: repo,
				Digest: map[string]string{
					"sha256": digest,
				},
			},
		},
	}
	if parseJSON {
		var data map[string]any
		if err := json.Unmarshal(rawPayload, &data); err != nil {
			return nil, err
		}
		dataObj, err := structpb.NewStruct(data)
		if err != nil {
			return nil, err
		}
		stmt.Predicate = dataObj
		return &Statement{Statement: stmt}, nil
	}
	legacyPredicate := string(rawPayload)
	return &Statement{
		Statement:       stmt,
		LegacyPredicate: &legacyPredicate,
	}, nil
}

func generateCycloneDXStatement(rawPayload []byte, digest string, repo string) (*Statement, error) {
	var data map[string]any
	if err := json.Unmarshal(rawPayload, &data); err != nil {
		return nil, err
	}
	dataObj, err := structpb.NewStruct(data)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Statement: &in_toto_attest.Statement{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: in_toto.PredicateCycloneDX,
			Subject: []*in_toto_attest.ResourceDescriptor{
				{
					Name: repo,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
			Predicate: dataObj,
		}}, nil
}

func checkRequiredJSONFields(rawPayload []byte, typ reflect.Type) error {
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	var tmp map[string]interface{}
	if err := json.Unmarshal(rawPayload, &tmp); err != nil {
		return err
	}
	// Create list of json tags, e.g. `json:"_type"`
	attributeCount := typ.NumField()
	allFields := make([]string, 0)
	for i := 0; i < attributeCount; i++ {
		jsonTagFields := strings.SplitN(typ.Field(i).Tag.Get("json"), ",", 2)
		if len(jsonTagFields) < 2 && jsonTagFields[0] != "" && jsonTagFields[0] != "-" {
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

func structToStruct(obj any) (*structpb.Struct, error) {
	toJSON, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var toMap map[string]any
	if err := json.Unmarshal(toJSON, &toMap); err != nil {
		return nil, err
	}
	toStruct, err := structpb.NewStruct(toMap)
	if err != nil {
		return nil, err
	}
	return toStruct, nil
}

func protoStructToStruct(obj proto.Message) (*structpb.Struct, error) {
	toJSON, err := protojson.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var toMap map[string]any
	if err := json.Unmarshal(toJSON, &toMap); err != nil {
		return nil, err
	}
	toStruct, err := structpb.NewStruct(toMap)
	if err != nil {
		return nil, err
	}
	return toStruct, nil
}
