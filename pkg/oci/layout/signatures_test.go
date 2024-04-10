package layout

import (
	"errors"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name      string
		layers    int
		wantError error
	}{
		{
			name:      "within limit",
			layers:    23,
			wantError: nil,
		},
		{
			name:      "exceeds limit",
			layers:    4242,
			wantError: errors.New("number of layers (4242) exceeded the limit (1000)"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := sigs{
				Image: &fake.FakeImage{
					ManifestStub: func() (*v1.Manifest, error) {
						return &v1.Manifest{
							Layers: make([]v1.Descriptor, test.layers),
						}, nil
					},
				},
			}
			_, err := s.Get()
			if test.wantError != nil && test.wantError.Error() != err.Error() {
				t.Fatalf("Get() = %v, wanted %v", err, test.wantError)
			}
			if test.wantError == nil && err != nil {
				t.Fatalf("Get() = %v, wanted %v", err, test.wantError)
			}
		})
	}
}
