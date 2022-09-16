package rootcerts

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
)

const fixturesDir = "./test-fixtures"
const caCertSHA256Sum = "e85d9f94f730878cc1a516d9486fdb0255452b37961f325af9fc851cc4689311"

func TestConfigureTLSHandlesNil(t *testing.T) {
	err := ConfigureTLS(nil, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestLoadCACertsHandlesNil(t *testing.T) {
	_, err := LoadCACerts(nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestLoadCACertsFromFile(t *testing.T) {
	path := testFixture("cafile", "cacert.pem")
	p, err := LoadCACerts(&Config{CAFile: path})
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	testCertLoaded(t, p)
}

func TestLoadCACertsInMem(t *testing.T) {
	path := testFixture("cafile", "cacert.pem")
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("err : %s", err)
	}
	p, err := LoadCACerts(&Config{CACertificate: pem})
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	testCertLoaded(t, p)
}

func TestLoadCACertsFromDir(t *testing.T) {
	path := testFixture("capath")
	p, err := LoadCACerts(&Config{CAPath: path})
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	testCertLoaded(t, p)
}

func TestLoadCACertsFromDirWithSymlinks(t *testing.T) {
	path := testFixture("capath-with-symlinks")
	p, err := LoadCACerts(&Config{CAPath: path})
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	testCertLoaded(t, p)
}

func testFixture(n ...string) string {
	parts := []string{fixturesDir}
	parts = append(parts, n...)
	return filepath.Join(parts...)
}

func testCertLoaded(t *testing.T, p *x509.CertPool) {
	switch len(p.Subjects()) {
	case 0:
		t.Fatal("expected a certificate in the pool")
	case 1:
		h := sha256.New()
		h.Write(p.Subjects()[0])
		sha256Sum := fmt.Sprintf("%x", h.Sum(nil))
		if caCertSHA256Sum != sha256Sum {
			t.Fatalf("sha256 sum mismatch; got '%x'; expected '%s'", sha256Sum, caCertSHA256Sum)
		}
	default:
		// Check if length is not zero
		for _, subj := range p.Subjects() {
			if len(subj) == 0 {
				t.Fatal("expected certificate with data included")
			}
		}
	}
}
