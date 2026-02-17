//
// Copyright 2026 The Sigstore Authors.
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

package gitlab

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestIsGroup(t *testing.T) {
	tests := []struct {
		name           string
		ref            string
		projectStatus  int
		groupStatus    int
		expectedResult bool
		expectError    bool
	}{
		{
			name:           "valid project reference",
			ref:            "owner/project",
			projectStatus:  http.StatusOK,
			groupStatus:    http.StatusNotFound,
			expectedResult: false,
			expectError:    false,
		},
		{
			name:           "valid group reference",
			ref:            "mygroup",
			projectStatus:  http.StatusNotFound,
			groupStatus:    http.StatusOK,
			expectedResult: true,
			expectError:    false,
		},
		{
			name:           "invalid reference - neither project nor group",
			ref:            "invalid/reference",
			projectStatus:  http.StatusNotFound,
			groupStatus:    http.StatusNotFound,
			expectedResult: false,
			expectError:    true,
		},
		{
			name:           "numeric project ID",
			ref:            "12345",
			projectStatus:  http.StatusOK,
			groupStatus:    http.StatusNotFound,
			expectedResult: false,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server that simulates GitLab API responses
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check if it's a project or group API call
				if r.URL.Path == "/api/v4/projects/"+tt.ref {
					w.WriteHeader(tt.projectStatus)
					if tt.projectStatus == http.StatusOK {
						w.Write([]byte(`{"id": 1, "name": "test-project"}`))
					}
					return
				}
				if r.URL.Path == "/api/v4/groups/"+tt.ref {
					w.WriteHeader(tt.groupStatus)
					if tt.groupStatus == http.StatusOK {
						w.Write([]byte(`{"id": 1, "name": "test-group"}`))
					}
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			// Create a GitLab client pointed at the test server
			client, err := gitlab.NewClient("test-token", gitlab.WithBaseURL(server.URL+"/api/v4"))
			if err != nil {
				t.Fatalf("failed to create test client: %v", err)
			}

			// Test the isGroup function
			result, err := isGroup(client, tt.ref)

			// Check error expectation
			if tt.expectError && err == nil {
				t.Errorf("expected an error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check result
			if result != tt.expectedResult {
				t.Errorf("expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestNew(t *testing.T) {
	gl := New()
	if gl == nil {
		t.Error("New() returned nil")
	}
}

func TestReferenceScheme(t *testing.T) {
	expected := "gitlab"
	if ReferenceScheme != expected {
		t.Errorf("ReferenceScheme = %q, want %q", ReferenceScheme, expected)
	}
}
