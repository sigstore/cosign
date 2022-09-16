package strutil

import (
	"fmt"
	"testing"
)

func BenchmarkRemoveDuplicates(b *testing.B) {
	a := make([]string, 1_000_000)
	for i := 0; i < len(a); i++ {
		a[i] = fmt.Sprintf("test.%d", i)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RemoveDuplicates(a, true)
	}
}

func BenchmarkRemoveDuplicatesStable(b *testing.B) {
	a := make([]string, 1_000_000)
	for i := 0; i < len(a); i++ {
		a[i] = fmt.Sprintf("test.%d", i)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RemoveDuplicatesStable(a, true)
	}
}

func BenchmarkEquivalentSlices(b *testing.B) {
	x := make([]string, 1_000_000)
	y := make([]string, len(x))
	for i := 0; i < len(x); i++ {
		x[i] = fmt.Sprintf("test.%d", i)
		y[i] = fmt.Sprintf("test.%d", i)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		EquivalentSlices(x, y)
	}
}
