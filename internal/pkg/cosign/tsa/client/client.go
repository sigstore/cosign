// Copyright 2023 The Sigstore Authors.
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

package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/digitorus/timestamp"
)

// TimestampAuthorityClient should be implemented by clients that want to request timestamp responses
type TimestampAuthorityClient interface {
	GetTimestampResponse(tsq []byte) ([]byte, error)
}

// TimestampAuthorityClient provides a client to query RFC 3161 timestamp authorities
type TimestampAuthorityClientImpl struct {
	TimestampAuthorityClient

	// URL is the path to the API to request timestamp responses
	URL string
	// CACert is the filepath to the PEM-encoded CA certificate for the connection to the TSA server
	CACert string
	// Cert is the filepath to the PEM-encoded certificate for the connection to the TSA server
	Cert string
	// Cert is the filepath to the PEM-encoded key corresponding to the certificate for the connection to the TSA server
	Key string
	// ServerName is the expected SAN value in the server's certificate - used for https://pkg.go.dev/crypto/tls#Config.ServerName
	ServerName string

	// Timeout is the request timeout
	Timeout time.Duration
}

const defaultTimeout = 10 * time.Second

func getHTTPTransport(cacertFilename, certFilename, keyFilename, serverName string, timeout time.Duration) (http.RoundTripper, error) {
	if timeout == 0 {
		timeout = defaultTimeout
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			CipherSuites: []uint16{
				// TLS 1.3 cipher suites.
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: true,
		},
		// the rest of default settings are copied verbatim from https://golang.org/pkg/net/http/#DefaultTransport
		// to minimize surprises for the users.
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	var pool *x509.CertPool
	if cacertFilename != "" {
		f, err := os.Open(cacertFilename)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		caCertBytes, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("unable to read CA certs from %s: %w", cacertFilename, err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertBytes) {
			return nil, fmt.Errorf("no valid CA certs found in %s", cacertFilename)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	if certFilename != "" && keyFilename != "" {
		cert, err := tls.LoadX509KeyPair(certFilename, keyFilename)
		if err != nil {
			return nil, fmt.Errorf("unable to read CA certs from cert %s, key %s: %w",
				certFilename, keyFilename, err)
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	if serverName != "" {
		tr.TLSClientConfig.ServerName = serverName
	}
	return tr, nil
}

// GetTimestampResponse sends a timestamp query to a timestamp authority, returning a timestamp response.
// The query and response are defined by RFC 3161.
func (t *TimestampAuthorityClientImpl) GetTimestampResponse(tsq []byte) ([]byte, error) {
	client := http.Client{
		Timeout: t.Timeout,
	}

	// if mTLS-related fields are set, create a custom Transport for the Client
	if t.CACert != "" || t.Cert != "" {
		tr, err := getHTTPTransport(t.CACert, t.Cert, t.Key, t.ServerName, t.Timeout)
		if err != nil {
			return nil, err
		}
		client.Transport = tr
	}

	req, err := http.NewRequest(http.MethodPost, t.URL, bytes.NewReader(tsq))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/timestamp-query")

	tsr, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to timestamp authority: %w", err)
	}
	defer tsr.Body.Close()
	if tsr.StatusCode != http.StatusOK && tsr.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("request to timestamp authority failed with status code %d", tsr.StatusCode)
	}

	resp, err := io.ReadAll(tsr.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading timestamp response: %w", err)
	}

	// validate that the timestamp response is parseable
	ts, err := timestamp.ParseResponse(resp)
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(os.Stderr, "Timestamp fetched with time: ", ts.Time)

	return resp, nil
}

func NewTSAClient(url string) *TimestampAuthorityClientImpl {
	return &TimestampAuthorityClientImpl{URL: url, Timeout: defaultTimeout}
}

func NewTSAClientMTLS(url, cacert, cert, key, serverName string) *TimestampAuthorityClientImpl {
	return &TimestampAuthorityClientImpl{
		URL:        url,
		CACert:     cacert,
		Cert:       cert,
		Key:        key,
		ServerName: serverName,
		Timeout:    defaultTimeout,
	}
}
