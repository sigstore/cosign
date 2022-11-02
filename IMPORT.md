# Import RSA and EC Keypairs
* Currently only supports RSA and ECDSA private keys

### Import a keypair

```shell
$ cosign import-key-pair --key opensslrsakey.pem
Enter password for private key:
Enter password for private key again:
Private key written to import-cosign.key
Public key written to import-cosign.pub
```
### Sign a container with imported keypair

```shell
$ cosign sign --key import-cosign.key $IMAGE_DIGEST
```
