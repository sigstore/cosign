package cli

import (
	"testing"
)

// Tests correctly formatted emails do not fail validEmail call
// Tests incorrectly formatted emails do not pass validEmail call
func TestEmailValid(t *testing.T) {
	goodEmail := "foo@foo.com"
	strongBadEmail := "foofoocom"

	if !validEmail(goodEmail) {
		t.Errorf("correct email %s, failed valid check", goodEmail)
	} else if validEmail(strongBadEmail) {
		t.Errorf("bad email %s, passed valid check", strongBadEmail)
	}
}
