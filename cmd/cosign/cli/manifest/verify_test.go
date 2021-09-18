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

package manifest

import (
	"reflect"
	"testing"
)

const singleContainerManifest = `
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

const initContainerManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: single-pod
spec:
  restartPolicy: Never
  initContainers:
    - name: preflight
      image: preflight:3.2.1
  containers:
    - name: nginx-container
      image: nginx:1.21.1
`

const multiContainerManifest = `
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

const multiResourceContainerManifest = `
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

const customContainerManifest = `
apiVersion: v42
kind: PodSpec
metadata:
  name: custom-pod
spec:
  restartPolicy: Never
  containers:
    - name: nginx-container
      image: nginx:1.21.1
`

const daemonsetManifest = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd-elasticsearch
  namespace: kube-system
  labels:
    k8s-app: fluentd-logging
spec:
  selector:
    matchLabels:
      name: fluentd-elasticsearch
  template:
    metadata:
      labels:
        name: fluentd-elasticsearch
    spec:
      tolerations:
      # this toleration is to have the daemonset runnable on master nodes
      # remove it if your masters can't run pods
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: NoSchedule
      initContainers:
      - name: py
        image: python
        command: ["python", "-c", "import math;print(math.sin(1))"]
      containers:
      - name: fluentd-elasticsearch
        image: quay.io/fluentd_elasticsearch/fluentd:v2.5.2
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
      terminationGracePeriodSeconds: 30
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
`

const jobManifest = `
apiVersion: batch/v1
kind: Job
metadata:
  name: pi
spec:
  template:
    spec:
      initContainers:
      - name: py
        image: python
        command: ["python", "-c", "import math;print(math.sin(1))"]
      containers:
      - name: pi
        image: perl
        command: ["perl",  "-Mbignum=bpi", "-wle", "print bpi(2000)"]
      restartPolicy: Never
  backoffLimit: 4
`

const cronJobManifest = `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "*/1 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          initContainers:
          - name: py
            image: python
            command: ["python", "-c", "booting up"]
          containers:
          - name: hello
            image: busybox
            imagePullPolicy: IfNotPresent
            command:
            - /bin/sh
            - -c
            - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure
`

func TestGetImagesFromYamlManifest(t *testing.T) {
	testCases := []struct {
		name         string
		fileContents []byte
		expected     []string
	}{{
		name:         "single image",
		fileContents: []byte(singleContainerManifest),
		expected:     []string{"nginx:1.21.1"},
	}, {
		name:         "init and container images",
		fileContents: []byte(initContainerManifest),
		expected:     []string{"preflight:3.2.1", "nginx:1.21.1"},
	}, {
		name:         "daemonsets",
		fileContents: []byte(daemonsetManifest),
		expected:     []string{"python", "quay.io/fluentd_elasticsearch/fluentd:v2.5.2"},
	}, {
		name:         "jobs",
		fileContents: []byte(jobManifest),
		expected:     []string{"python", "perl"},
	}, {
		name:         "cronjobs",
		fileContents: []byte(cronJobManifest),
		expected:     []string{"python", "busybox"},
	}, {
		name:         "multi image",
		fileContents: []byte(multiContainerManifest),
		expected:     []string{"nginx:1.21.1", "ubuntu:21.10"},
	}, {
		name:         "multiple resources and images within a document",
		fileContents: []byte(multiResourceContainerManifest),
		expected:     []string{"nginx:1.14.2", "nginx:1.21.1", "ubuntu:21.10"},
	}, {
		name:         "no images found",
		fileContents: []byte(``),
		expected:     nil,
	}, {
		name:         "custom type single image",
		fileContents: []byte(customContainerManifest),
		expected:     []string{"nginx:1.21.1"},
	}}
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
