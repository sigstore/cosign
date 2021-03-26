# Fun Tips And Tricks!

## Signing Git Commits - Three Ways!

You thought Git signatures were always GPG?
Think again!

### Easy Mode

Sign the commits and store the signatures and public keys somewhere else.

```
$ ./cosign sign-blob -key cosign.key <(git rev-parse HEAD)
Using payload from: /dev/fd/63
Enter password for private key:
MEUCIQDLtTbCRCW+o7Gt3WKR4b2UqT947L8JtYzQJk+R8PItxgIgXoYQg1YXw8xDmGWun6wIG2t+/J0HJs9SbscnSLMNWsM=
$ git rev-parse HEAD
455d1988360dcfdcf0fa17b0736fbbc33b4924c0
$ ./cosign verify-blob -key cosign.pub -signature MEUCIQDLtTbCRCW+o7Gt3WKR4b2UqT947L8JtYzQJk+R8PItxgIgXoYQg1YXw8xDmGWun6wIG2t+/J0HJs9SbscnSLMNWsM= <(git rev-parse HEAD)
Verified OK
```

### Medium Mode

Store the signature in the repo as notes, store the public key somewhere else.

```
$ ./cosign sign-blob -key cosign.key <(git rev-parse HEAD)
Using payload from: /dev/fd/63
Enter password for private key:
MEQCIHXN31pDrZBxs+m/HrcFruavv++oMc+pBZKgl7Hps9jjAiA9QE5uzpFNC5SGpdr4TJuCwh47C24Hwt4yHICae0J1bw==
$ git notes add -m "MEQCIHXN31pDrZBxs+m/HrcFruavv++oMc+pBZKgl7Hps9jjAiA9QE5uzpFNC5SGpdr4TJuCwh47C24Hwt4yHICae0J1bw==" HEAD
$ ./cosign verify-blob -key cosign.pub -signature <(git notes show HEAD) <(git rev-parse HEAD)
Verified OK
```


### Hard Mode

Store the signature in the Transparency Log, and store the public key somewhere else.

```
$ COSIGN_EXPERIMENTAL=1 ./cosign sign-blob -key cosign.key <(git rev-parse HEAD)
Using payload from: /dev/fd/63
Enter password for private key:
MEYCIQDWX6RjU0Z2ynd1CdiAwo/JaC2Z5+vdx8H5spuDNu/r5wIhAPnP+87+knFEwbE8FgeXCrgkjWal3aBsNR3IVaBDT2XU
tlog entry created with index:  1224
```

Now find it from the log:

```
$ uuid=$(rekor-cli search --artifact <(git rev-parse HEAD) | tail -n 1)
$ sig=$(rekor-cli get --uuid=$uuid --format=json | jq -r .Body | base64 -D | jq -r .spec.signature.content)
$ cosign verify-blob -key cosign.pub -signature <(echo $sig) <(git rev-parse HEAD)
Verified OK
```

### Level 11

Store the signature in the Transparency Log and don't store the keys anywhere.

**COMING SOON**
