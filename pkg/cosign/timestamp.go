package cosign

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/digitorus/timestamp"
)

// GetTimestamp returns a base64-encoded, DER-encoded RFC3161 TimestampResponse
func GetTimestamp(addr string, payload []byte) (string, error) {
	tsq, err := timestamp.CreateRequest(bytes.NewReader(payload), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
	})
	if err != nil {
		return "", err
	}

	tsr, err := http.Post(addr, "application/timestamp-query", bytes.NewReader(tsq))
	if err != nil {
		return "", err
	}

	if tsr.StatusCode > 200 {
		return "", err
	}

	resp, err := ioutil.ReadAll(tsr.Body)
	if err != nil {
		return "", err
	}

	tsResp, err := timestamp.ParseResponse(resp)
	if err != nil {
		return "", err
	}

	// Make sure the response has the right hash
	h := sha256.New()
	if _, err := h.Write(payload); err != nil {
		return "", err
	}
	dgst := h.Sum(nil)

	if !bytes.Equal(dgst, tsResp.HashedMessage) {
		return "", errors.New("mismatched hash from timestamp server")
	}

	return base64.StdEncoding.EncodeToString(resp), nil
}
