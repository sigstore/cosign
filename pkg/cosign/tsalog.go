package cosign

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"os"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore/pkg/tuf"
)

var tsaLeafCertStr = `tsa_leaf.crt.pem`
var tsaRootCertStr = `tsa_root.crt.pem`
var tsaIntermediateCertStrPattern = `tsa_intermediate_%d.crt.pem`

// GetTSACerts retrieves trusted TSA certificates from the embedded or cached
// TUF root. If expired, makes a network call to retrieve the updated targets.
// By default, the certificates come from TUF, but you can override this for test
// purposes by using an env variable `SIGSTORE_TSA_CERTIFICATE_FILE`. If using
// an alternate, the file should be in PEM format.
func GetTSACerts(ctx context.Context) (leaves [][]byte, intermediates [][]byte, roots [][]byte, err error) {
	altTSACert := env.Getenv(env.VariableSigstoreTSACertificateFile)

	if altTSACert != "" {
		raw, err := os.ReadFile(altTSACert)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error reading alternate TSA certificate file: %w", err)
		}
		leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error splitting TSA certificate chain: %w", err)
		}

		leavesPEM, intermediatesPEM, rootsPEM := convertCertsToPEM(leaves), convertCertsToPEM(intermediates), convertCertsToPEM(roots)
		return leavesPEM, intermediatesPEM, rootsPEM, nil
	} else {
		tufClient, err := tuf.NewFromEnv(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		leafCert, err := tufClient.GetTarget(tsaLeafCertStr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error fetching TSA leaf certificate: %w", err)
		}
		rootCert, err := tufClient.GetTarget(tsaRootCertStr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error fetching TSA root certificate: %w", err)
		}
		var intermediates [][]byte
		for i := 0; ; i++ {
			intermediateCertStr := fmt.Sprintf(tsaIntermediateCertStrPattern, i)
			intermediateCert, err := tufClient.GetTarget(intermediateCertStr)
			if err != nil {
				break
			}
			intermediates = append(intermediates, intermediateCert)
		}
		return [][]byte{leafCert}, intermediates, [][]byte{rootCert}, nil
	}
}

func convertCertsToPEM(certs []*x509.Certificate) [][]byte {
	var pemCerts [][]byte
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemCerts = append(pemCerts, pem.EncodeToMemory(block))
	}
	return pemCerts
}
