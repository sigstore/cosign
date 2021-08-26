# Cosigned Admission Webhook

## Requirements
* Kind (or any other Kubernetes cluster successfully configured).
* Helm.

## Run `cosigned`

Cosigned requires `cert-manager` to be pre-configured on the running cluster.
To install `cert-manager` follow the next steps:

```shell
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.5.0 \
  --set installCRDs=true
```

Once `cert-manager` is installed in your cluster, you can start configuring `cosigned`.

Generate a keypair to validate the signatures of the deployed Kubernetes resources and their images:

```shell
cosign generate-key-pair
```

The previous command generates two key files `cosign.key` and `cosign.pub`. Next, create a secret to validate the signatures:

```shell
kubectl create secret generic mysecret -n cosigned --from-file=cosign.pub=./cosign.pub
```

Install `cosigned` using Helm and setting the value of the secret key reference to `k8s://cosigned/mysecret`:

```shell
helm install cosigned -n cosigned chart/cosigned --replace --set webhook.secretKeyRef.name=k8s://cosigned/mysecret --create-namespace
```

Validate the `cosigned` functionality by create a `Deployment` with and without signed images:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-unsigned
  labels:
    app: nginx
spec:
  replicas: 1
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
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-signed
  labels:
    app: nginx
spec:
  replicas: 1
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
        image: hectorj2f/nginx
        ports:
        - containerPort: 80
```

