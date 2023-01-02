// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ui_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/stretchr/testify/assert"
)

func TestConfirm(t *testing.T) {
	cases := []struct {
		name            string
		input           string
		expected        error
		expectedMessage string
	}{
		{"no", "n\n", &ui.ErrPromptDeclined{}, "user declined"},
		{"no-upper", "N\n", &ui.ErrPromptDeclined{}, "user declined"},
		{"yes", "y\n", nil, ""},
		{"yes-upper", "Y\n", nil, ""},
		{"default", "\n", &ui.ErrPromptDeclined{}, "user declined"},
		{"empty", "", &ui.ErrPromptDeclined{}, "user declined"},
		{"invalid", "yy", &ui.ErrInvalidInput{Got: "yy", Allowed: "y, n"}, "invalid input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stderr := ui.RunWithTestCtx(func(ctx context.Context, write ui.WriteFunc) {
				write(tc.input)
				err := ui.ConfirmContinue(ctx)
				assert.EqualValues(t, tc.expected, err)
				if len(tc.expectedMessage) > 0 {
					assert.ErrorContains(t, err, "")
				}
			})
			assert.Equal(t, "Are you sure you would like to continue? [y/N] ", stderr, "Bad output to STDERR")
		})
	}
}

type BadReader struct{}

// BadReader implements Reader.
func (b *BadReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("my error")
}

func TestConfirmError(t *testing.T) {
	var stderr bytes.Buffer
	stdin := BadReader{}
	ctx := ui.WithEnv(context.Background(), &ui.Env{&stderr, &stdin})
	assert.ErrorContains(t, ui.ConfirmContinue(ctx), "my error")
}
