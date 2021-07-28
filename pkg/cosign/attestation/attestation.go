package attestation

import (
	"encoding/json"
	"fmt"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"io/ioutil"
	"path/filepath"
	"reflect"
)

const (
	// CosignCustomPredicateType specifies the type of the Predicate.
	CosignCustomPredicateType = "cosign.sigstore.dev/attestation/v1"
)

// CosignAttestation specifies the format of the Custom Predicate.
type CosignAttestation struct {
	Data string
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
		return generateCustomStatement(rawPayload, opts.Digest, opts.Repo)
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
func generateCustomStatement(rawPayload []byte, digest, repo string) (interface{}, error) {
	return in_toto.Statement{
		StatementHeader: generateStatementHeader(digest, repo, in_toto.StatementInTotoV01),
		Predicate: CosignAttestation{
			Data: string(rawPayload),
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
		Predicate: CosignAttestation{
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
		allFields = append(allFields, typ.Field(i).Tag.Get("json"))
	}

	// Assert that there's a key in the passed map for each tag
	for _, field := range allFields {
		if _, ok := tmp[field]; !ok {
			return fmt.Errorf("required field %s missing", field)
		}
	}
	return nil
}
