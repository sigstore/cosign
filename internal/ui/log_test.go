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
	"context"
	"testing"

	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/stretchr/testify/assert"
)

type testCase struct {
	name     string
	input    string
	args     []any
	expected string
}

func TestInfo(t *testing.T) {
	cases := []testCase{
		{"basic", "foo", nil, "foo\n"},
		{"multiline", "foo\nbar", nil, "foo\nbar\n"},
		{"fmt", "foo: %v", []any{"bar"}, "foo: bar\n"},
	}
	for _, tc := range cases {
		stderr := ui.RunWithTestCtx(func(ctx context.Context, write ui.WriteFunc) {
			ui.Info(ctx, tc.input, tc.args...)
		})
		assert.Equal(t, tc.expected, stderr, "Bad output to STDERR")
	}
}

func TestWarn(t *testing.T) {
	cases := []testCase{
		{"basic", "foo", nil, "WARNING: foo\n"},
		{"multiline", "foo\nbar", nil, "WARNING: foo\nbar\n"},
		{"fmt", "bar: %v", []any{"baz"}, "WARNING: bar: baz\n"},
	}
	for _, tc := range cases {
		stderr := ui.RunWithTestCtx(func(ctx context.Context, write ui.WriteFunc) {
			ui.Warn(ctx, tc.input, tc.args...)
		})
		assert.Equal(t, tc.expected, stderr, "Bad output to STDERR")
	}
}
