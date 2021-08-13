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

import (
	"reflect"
	"testing"
)

const SingleContainerManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: single-pod
spec:
  restartPolicy: Never
  containers:
    - name: nginx-container
      image: nginx:1.21.1
`

const MultiContainerManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: multi-pod
spec:
  restartPolicy: Never
  volumes:
    - name: shared-data
      emptyDir: {}
  containers:
    - name: nginx-container
      image: nginx:1.21.1
      volumeMounts:
        - name: shared-data
          mountPath: /usr/share/nginx/html
    - name: ubuntu-container
      image: ubuntu:21.10
      volumeMounts:
        - name: shared-data
          mountPath: /pod-data
      command: ["/bin/sh"]
      args: ["-c", "echo Hello, World > /pod-data/index.html"]
`
const MultiResourceContainerManifest = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: multi-pod
spec:
  restartPolicy: Never
  volumes:
    - name: shared-data
      emptyDir: {}
  containers:
    - name: nginx-container
      image: nginx:1.21.1
      volumeMounts:
        - name: shared-data
          mountPath: /usr/share/nginx/html
    - name: ubuntu-container
      image: ubuntu:21.10
      volumeMounts:
        - name: shared-data
          mountPath: /pod-data
      command: ["/bin/sh"]
      args: ["-c", "echo Hello, World > /pod-data/index.html"]
`

func TestGetImagesFromYamlManifest(t *testing.T) {
	testCases := []struct {
		name         string
		fileContents []byte
		expected     []string
	}{
		{
			name:         "single image",
			fileContents: []byte(SingleContainerManifest),
			expected:     []string{"nginx:1.21.1"},
		},
		{
			name:         "multi image",
			fileContents: []byte(MultiContainerManifest),
			expected:     []string{"nginx:1.21.1", "ubuntu:21.10"},
		},
		{
			name:         "multiple resources and images within a document",
			fileContents: []byte(MultiResourceContainerManifest),
			expected:     []string{"nginx:1.14.2", "nginx:1.21.1", "ubuntu:21.10"},
		},
		{
			name:         "no images found",
			fileContents: []byte(``),
			expected:     nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getImagesFromYamlManifest(tc.fileContents)
			if err != nil {
				t.Fatalf("getImagesFromYamlManifest returned error: %v", err)
			}
			if !reflect.DeepEqual(tc.expected, got) {
				t.Errorf("getImagesFromYamlManifest returned %v, wanted %v", got, tc.expected)
			}
		})
	}
}
