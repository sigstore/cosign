package oci

import "fmt"

// MaxLayersExceeded is an error indicating that the artifact has too many layers and cosign should abort processing it.
type MaxLayersExceeded struct {
	value   int64
	maximum int64
}

func NewMaxLayersExceeded(value, maximum int64) *MaxLayersExceeded {
	return &MaxLayersExceeded{value, maximum}
}

func (e *MaxLayersExceeded) Error() string {
	return fmt.Sprintf("number of layers (%d) exceeded the limit (%d)", e.value, e.maximum)
}
