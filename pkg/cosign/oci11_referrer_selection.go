package cosign

import (
	"sort"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func deterministicLastDescriptorByDigest(descriptors []v1.Descriptor) v1.Descriptor {
	sorted := append([]v1.Descriptor(nil), descriptors...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Digest.String() < sorted[j].Digest.String() })
	return sorted[len(sorted)-1]
}
