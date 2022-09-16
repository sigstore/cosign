package va

import "strings"

// replaceInvalidUTF8 replaces all invalid UTF-8 encodings with
// Unicode REPLACEMENT CHARACTER.
func replaceInvalidUTF8(input []byte) string {
	var b strings.Builder

	// Ranging over a string in Go produces runes. When the range keyword
	// encounters an invalid UTF-8 encoding, it returns REPLACEMENT CHARACTER.
	for _, v := range string(input) {
		b.WriteRune(v)
	}
	return b.String()
}
