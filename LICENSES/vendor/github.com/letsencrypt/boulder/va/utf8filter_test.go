package va

import "testing"

func TestReplaceInvalidUTF8(t *testing.T) {
	input := "f\xffoo"
	expected := "f\ufffdoo"
	result := replaceInvalidUTF8([]byte(input))
	if result != expected {
		t.Errorf("replaceInvalidUTF8(%q): got %q, expected %q", input, result, expected)
	}
}
