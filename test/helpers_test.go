//go:build e2e

package test

import "testing"

func TestGenerateCertificateBundle(t *testing.T) {
	for _, test := range []struct {
		name            string
		genIntermediate bool
	}{
		{
			name:            "without intermediate",
			genIntermediate: false,
		},
		{
			name:            "with intermediate",
			genIntermediate: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, _, _, _, _, _, err := generateCertificateBundle(true)
			if err != nil {
				t.Fatalf("Error generating certificate bundle: %v", err)
			}
		})
	}
}
