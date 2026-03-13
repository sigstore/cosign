package cosign

import (
	"crypto/x509"
	"fmt"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sigstorebundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type InternalTrustMaterial struct {
	root.TrustedMaterial
	UntrustedBundleCA []*x509.Certificate
}

func NewInternalTrustMaterial(trustedMaterial root.TrustedMaterial, entity verify.SignedEntity) (*InternalTrustMaterial, error) {
	certificateAuthorities, err := getUntrustedIntermediateCA(entity)
	if err != nil {
		// Use Base Trust Material if Intermediate CA Not Found in Bundle
		return &InternalTrustMaterial{
			TrustedMaterial:   trustedMaterial,
			UntrustedBundleCA: nil,
		}, nil
	}

	return &InternalTrustMaterial{
		TrustedMaterial:   trustedMaterial,
		UntrustedBundleCA: certificateAuthorities,
	}, nil
}

func getUntrustedIntermediateCA(entity verify.SignedEntity) ([]*x509.Certificate, error) {
	if entity == nil {
		return nil, fmt.Errorf("entity is nil")
	}

	bundleEntity, ok := entity.(*sigstorebundle.Bundle)
	if !ok {
		return nil, fmt.Errorf("entity type %T is not *bundle.Bundle", entity)
	}

	// Access Embedded protobundle.Bundle
	// bundle.Bundle Embeds *protobundle.Bundle
	b := bundleEntity.Bundle
	if b == nil || b.VerificationMaterial == nil {
		return nil, fmt.Errorf("bundle or verification material is nil")
	}

	switch content := b.VerificationMaterial.GetContent().(type) {
	case *protobundle.VerificationMaterial_X509CertificateChain:
		certificates := content.X509CertificateChain.GetCertificates()

		if len(certificates) == 0 {
			return nil, fmt.Errorf("no certificates in bundle verification material")
		}

		if len(certificates) > 10 {
			return nil, fmt.Errorf("certificate chain too long: %d certificates (max 10)", len(certificates))
		}

		// Parse All Certificates from Chain and Identify Intermediate CA
		// Extract All Except Leaf Certificate and Root Certificate Authority
		certificateAuthorities := make([]*x509.Certificate, 0)
		for i, certificate := range certificates {
			cert, err := x509.ParseCertificate(certificate.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
			}

			validCA := cert.BasicConstraintsValid && cert.IsCA
			selfSignedCA := cert.Subject.String() == cert.Issuer.String()

			if validCA && !selfSignedCA {
				certificateAuthorities = append(certificateAuthorities, cert)
			}
		}

		return certificateAuthorities, nil
	}

	return nil, fmt.Errorf("bundle verification material is not a x509 certificate chain")
}

// FulcioCertificateAuthorities wraps the base TrustedMaterial's CAs with InternalCertificateAuthority
// that can use the bundle's intermediate certificates.
func (t *InternalTrustMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	certificateAuthorities := t.TrustedMaterial.FulcioCertificateAuthorities()

	if len(t.UntrustedBundleCA) == 0 {
		return certificateAuthorities
	}

	internalCa := make([]root.CertificateAuthority, len(certificateAuthorities))
	for index, ca := range certificateAuthorities {
		internalCa[index] = &InternalCertificateAuthority{
			TrustedCertificateAuthority: ca,
			UntrustedIntermediateCA:     t.UntrustedBundleCA,
		}
	}

	return internalCa
}

// InternalCertificateAuthority wraps a CertificateAuthority and adds support for
// using intermediate certificates from the bundle during verification.
type InternalCertificateAuthority struct {
	TrustedCertificateAuthority root.CertificateAuthority
	UntrustedIntermediateCA     []*x509.Certificate
}

// Verify attempts to verify the leaf certificate using the trusted CA.
// If that fails, it tries again using intermediate certificates from the bundle.
func (c *InternalCertificateAuthority) Verify(leafCertificate *x509.Certificate, observerTimestamp time.Time) ([][]*x509.Certificate, error) {
	// Try To Verify With The Standard Trusted Certificate Authority First
	certificateChains, err := c.TrustedCertificateAuthority.Verify(leafCertificate, observerTimestamp)
	if err == nil {
		return certificateChains, nil
	}

	// If No Intermediate CAs From Bundle, Return The Original Error
	if len(c.UntrustedIntermediateCA) == 0 {
		return nil, err
	}

	// Try To Get The Root Certificate From The Trusted CA
	ca, ok := c.TrustedCertificateAuthority.(*root.FulcioCertificateAuthority)
	if !ok {
		return nil, fmt.Errorf("trusted certificate authority is not a fulcio certificate authority: %w", err)
	}

	// Check Validity Period Of The Trusted Certificate Authority
	if !ca.ValidityPeriodStart.IsZero() && observerTimestamp.Before(ca.ValidityPeriodStart) {
		return nil, fmt.Errorf("certificate is not valid yet")
	}
	if !ca.ValidityPeriodEnd.IsZero() && observerTimestamp.After(ca.ValidityPeriodEnd) {
		return nil, fmt.Errorf("certificate is no longer valid")
	}

	// Build Verification Options With Intermediate CAs From The Bundle
	rootCertificatePool := x509.NewCertPool()
	rootCertificatePool.AddCert(ca.Root)

	intermediateCertificatePool := x509.NewCertPool()
	for _, intermediateCA := range c.UntrustedIntermediateCA {
		intermediateCertificatePool.AddCert(intermediateCA)
	}

	opts := x509.VerifyOptions{
		Roots:         rootCertificatePool,
		Intermediates: intermediateCertificatePool,
		CurrentTime:   observerTimestamp,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	}

	return leafCertificate.Verify(opts)
}
