package cosign

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
	"os"
	"path/filepath"
)

const (
	tsaLeafCertStr                = `tsa_leaf.crt.pem`
	tsaRootCertStr                = `tsa_root.crt.pem`
	tsaIntermediateCertStrPattern = `tsa_intermediate_%d.crt.pem`
)

type TSACertificate struct {
	RootCert         []*x509.Certificate
	IntermediateCert []*x509.Certificate
	LeafCert         *x509.Certificate
}

// GetTSACerts retrieves trusted TSA certificates from the embedded or cached
// TUF root. If expired, makes a network call to retrieve the updated targets.
// By default, the certificates come from TUF, but you can override this for test
// purposes by using an env variable `SIGSTORE_TSA_CERTIFICATE_FILE`. If using
// an alternate, the file should be in PEM format.
func GetTSACerts(ctx context.Context, tsaCertChainPath string) (*TSACertificate, error) {
	rootEnv := env.Getenv(env.VariableSigstoreTSACertificateFile)
	if tsaCertChainPath != "" {
		return getTsaCertFromFile(tsaCertChainPath)
	}
	if rootEnv != "" {
		return getEnvCertFile(rootEnv)
	}
	return getTsaCertFromTufRoot(ctx)
}

func getTsaCertFromFile(tsaCertChainPath string) (*TSACertificate, error) {
	var tsaCertificate = TSACertificate{}
	_, err := os.Stat(tsaCertChainPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open timestamp certificate chain file: %w", err)
	}
	pemBytes, err := os.ReadFile(filepath.Clean(tsaCertChainPath))
	if err != nil {
		return nil, fmt.Errorf("error reading certification chain path file: %w", err)
	}

	leaves, intermediates, roots, err := splitPEMCertificateChain(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("error splitting certificates: %w", err)
	}
	if len(leaves) != 1 {
		return nil, fmt.Errorf("certificate chain must contain at most one TSA certificate")
	}
	if len(leaves) == 1 {
		tsaCertificate.LeafCert = leaves[0]
	}
	tsaCertificate.IntermediateCert = intermediates
	tsaCertificate.RootCert = roots
	return &tsaCertificate, nil
}

func getTsaCertFromTufRoot(ctx context.Context) (*TSACertificate, error) {
	var tsaCertificate = TSACertificate{}
	var tmpCerts []*x509.Certificate
	tufClient, err := tuf.NewFromEnv(ctx)
	if err != nil {
		return nil, err
	}
	leafCert, err := tufClient.GetTarget(tsaLeafCertStr)
	if err != nil {
		return nil, fmt.Errorf("error fetching TSA leaf certificate: %w", err)
	}

	rootCert, err := tufClient.GetTarget(tsaRootCertStr)
	if err != nil {
		return nil, fmt.Errorf("error fetching TSA root certificate: %w", err)
	}

	if tsaCertificate.RootCert, err = cryptoutils.UnmarshalCertificatesFromPEM(rootCert); err != nil {
		return nil, fmt.Errorf("error unmarshal TSA root certificate: %w", err)
	}

	if tmpCerts, err = cryptoutils.UnmarshalCertificatesFromPEM(leafCert); err != nil {
		return nil, fmt.Errorf("error unmarshal TSA leaf certificate: %w", err)
	}

	if len(tmpCerts) > 1 {
		return nil, fmt.Errorf("certificate chain must contain at most one TSA certificate")
	}

	if len(tmpCerts) == 1 {
		tsaCertificate.LeafCert = tmpCerts[0]
	}

	for i := 0; ; i++ {
		intermediateCertStr := fmt.Sprintf(tsaIntermediateCertStrPattern, i)
		intermediateRawCert, err := tufClient.GetTarget(intermediateCertStr)
		if err != nil {
			break
		}
		intermediateCert, err := cryptoutils.UnmarshalCertificatesFromPEM(intermediateRawCert)
		if err != nil {
			return nil, fmt.Errorf("error unmarshal TSA intermediate certificate: %w", err)
		}
		tsaCertificate.IntermediateCert = append(tsaCertificate.IntermediateCert, intermediateCert...)
	}
	return &tsaCertificate, nil
}

func getEnvCertFile(rootEnv string) (*TSACertificate, error) {
	var tsaCertificate = TSACertificate{}
	raw, err := os.ReadFile(rootEnv)
	if err != nil {
		return nil, fmt.Errorf("error reading certification chain file from env: %w", err)
	}
	leaves, intermediates, roots, err := splitPEMCertificateChain(raw)
	if err != nil {
		return nil, fmt.Errorf("error splitting certificates: %w", err)
	}
	if len(leaves) > 1 {
		return nil, fmt.Errorf("certificate chain must contain at most one TSA certificate")
	}
	if len(leaves) == 1 {
		tsaCertificate.LeafCert = leaves[0]
	}
	tsaCertificate.IntermediateCert = intermediates
	tsaCertificate.RootCert = roots
	return &tsaCertificate, nil
}

// splitPEMCertificateChain returns a list of leaf (non-CA) certificates, a certificate pool for
// intermediate CA certificates, and a certificate pool for root CA certificates
func splitPEMCertificateChain(pem []byte) (leaves, intermediates, roots []*x509.Certificate, err error) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pem)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, cert := range certs {
		if !cert.IsCA {
			leaves = append(leaves, cert)
		} else {
			// root certificates are self-signed
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				roots = append(roots, cert)
			} else {
				intermediates = append(intermediates, cert)
			}
		}
	}

	return leaves, intermediates, roots, nil
}
