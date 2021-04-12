//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import "testing"

func TestOneOf(t *testing.T) {
	type dumbStruct struct {
		A int
		B []string
		C bool
	}
	tests := []struct {
		name string
		args []interface{}
		want bool
	}{
		{
			name: "3/3",
			args: []interface{}{"one", 2, true},
			want: false,
		},
		{
			name: "2/3",
			args: []interface{}{"one", 2, false},
			want: false,
		},
		{
			name: "1/3",
			args: []interface{}{"", 2, false},
			want: true,
		},
		{
			name: "0/1",
			args: []interface{}{""},
			want: false,
		},
		{
			name: "1/1",
			args: []interface{}{"hey"},
			want: true,
		},
		{
			name: "structs",
			args: []interface{}{"hey", dumbStruct{A: 2}},
			want: false,
		},
		{
			name: "struct",
			args: []interface{}{"", dumbStruct{A: 2}},
			want: true,
		},
		{
			name: "pointers",
			args: []interface{}{"hey", &struct{ a int }{a: 2}, false},
			want: false,
		},
		{
			name: "pointer",
			args: []interface{}{&struct{ a int }{a: 2}, false},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := oneOf(tt.args...); got != tt.want {
				t.Errorf("oneOf() = %v, want %v", got, tt.want)
			}
		})
	}
}
